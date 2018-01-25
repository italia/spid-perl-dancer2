package Dancer2::Plugin::SPID;
use Dancer2::Plugin;

has '_spid'         => (is => 'lazy');
has '_on_login'     => (is => 'rw');
has '_on_logout'    => (is => 'rw');
has 'spid_button'   => (is => 'lazy', plugin_keyword => 1);

use Carp;
use Crypt::JWT qw(encode_jwt decode_jwt);
use Net::SPID;
use URI::Escape;

plugin_hooks qw(before_login after_login before_logout after_logout);

my $DEFAULT_JWT_SECRET = 'default.jwt.secret';

sub _build__spid {
    my ($self) = @_;
    
    # Initialize our Net::SPID object with information about this SP and the
    # CA certificate used for validation of IdP certificates (if cacert_file
    # is omitted, CA validation is skipped).
    my $spid = Net::SPID->new(
        sp_entityid     => $self->config->{sp_entityid},
        sp_key_file     => $self->config->{sp_key_file},
        sp_cert_file    => $self->config->{sp_cert_file},
        cacert_file     => $self->config->{cacert_file},
    );
    
    # Load Identity Providers from their XML metadata.
    $spid->load_idp_metadata($self->config->{idp_metadata_dir});

    return $spid;
}

sub _build_spid_button {
    my ($self, %args) = @_;
    
    return $self->_spid->get_button($self->config->{login_endpoint} . '?idp=%s');
}

sub spid_on_login :PluginKeyword {
    my ($self, $cb) = @_;
    $self->_on_login($cb);
}

sub spid_on_logout :PluginKeyword {
    my ($self, $cb) = @_;
    $self->_on_logout($cb);
}

sub spid_session :PluginKeyword {
    my ($self) = @_;
    return $self->dsl->session('__spid_session');
}

sub BUILD {
    my ($self) = @_;
    
    # Check that we have all the required config options.
    foreach my $key (qw(sp_entityid sp_key_file sp_cert_file idp_metadata_dir)) {
        croak "Missing required config option for SPID: '$key'"
            if !$self->config->{$key};
    }
    
    # Create a hook for populating the spid_* variables in templates.
    $self->app->add_hook(Dancer2::Core::Hook->new(
        name => 'before_template_render',
        code => sub {
            my $vars = shift;
            
            my $url_cb = sub {
                my ($idp_id, %args) = @_;
                
                my $jwt = encode_jwt(
                    payload => {
                        idp         => $idp_id,
                        level       => ($args{level} || 1),
                        redirect    => ($args{redirect} || '/'),
                    },
                    alg => 'HS256',
                    key => $self->config->{jwt_secret} // $DEFAULT_JWT_SECRET,
                );
                sprintf '%s?t=%s',
                    $self->config->{login_endpoint},
                    $jwt;
            };
            
            $vars->{spid_button} = sub {
                my %args = %{$_[0]};
                $self->_spid->get_button($url_cb, %args);
            };
            
            $vars->{spid_login} = sub {
                my %args = %{$_[0]};
                $url_cb->($self->spid_session->idp_id, %args);
            };
            
            $vars->{spid_logout} = sub {
                my %args = %{$_[0]};
                
                sprintf '%s?redirect=%s',
                    $self->config->{logout_endpoint},
                    ($args{redirect} || '/');
            };
            
            $vars->{spid_session} = sub { $self->spid_session };
        }
    ));
    
    # Create a route for the login endpoint.
    # This endpoint initiates SSO through the user-chosen Identity Provider.
    $self->app->add_route(
        method  => 'get',
        regexp  => $self->config->{login_endpoint},
        code    => sub {
            $self->execute_plugin_hook('before_login');
            
            my $jwt = decode_jwt(
                token   => $self->dsl->param('t'),
                key     => $self->config->{jwt_secret} // $DEFAULT_JWT_SECRET,
            );
            
            # Check that we have the mandatory 'idp' parameter and that it matches
            # an available Identity Provider.
            my $idp = $self->_spid->get_idp($jwt->{idp})
                or return $self->dsl->status(400);
    
            # Craft the AuthnRequest.
            my $authnreq = $idp->authnrequest(
                #acs_url     => 'http://localhost:3000/spid-sso',
                acs_index   => 0,
                attr_index  => 1,
                level       => $jwt->{level} || 1,
            );
    
            # Save the ID of the Authnreq so that we can check it in the response
            # in order to prevent forgery.
            $self->dsl->session('__spid_authnreq_id' => $authnreq->id);
            
            # Save the redirect destination to be used after successful login.
            $self->dsl->session('__spid_sso_redirect' => $jwt->{redirect} || '/');
    
            # Redirect user to the IdP using its HTTP-Redirect binding.
            $self->dsl->redirect($authnreq->redirect_url, 302);
        },
    );
    
    # Create a route for the SSO endpoint (AssertionConsumerService).
    # During SSO, the Identity Provider will redirect user to this URL POSTing
    # the resulting assertion.
    $self->app->add_route(
        method  => 'post',
        regexp  => $self->config->{sso_endpoint},
        code    => sub {
            # Parse and verify the incoming assertion. This may throw exceptions so we
            # enclose it in an eval {} block.
            my $assertion = eval {
                $self->_spid->parse_assertion(
                    $self->dsl->param('SAMLResponse'),
                    $self->dsl->session('__spid_authnreq_id'),  # Match the ID of our authentication request for increased security.
                );
            };
            
            # Clear the ID of the outgoing Authnreq, regardless of the result.
            $self->dsl->session('__spid_authnreq_id' => undef);
            
            # TODO: better error handling:
            # - authentication failure
            # - authentication cancelled by user
            # - temporary server error
            # - unavailable SPID level
            
            # In case of SSO failure, display an error page.
            if (!$assertion) {
                $self->dsl->warning("Bad Assertion received: $@");
                $self->dsl->status(400);
                $self->dsl->content_type('text/plain');
                return "Bad Assertion: $@";
            }
            
            # Login successful! Initialize our application session and store
            # the SPID information for later retrieval.
            # $assertion->spid_session is a Net::SPID::Session object which is a
            # simple hashref thus it's easily serializable.
            # TODO: this should be stored in a database instead of the current Dancer
            # session, and it should be indexed by SPID SessionID so that we can delete
            # it when we get a LogoutRequest from an IdP.
            $self->dsl->session('__spid_session' => $assertion->spid_session);
            
            # TODO: handle SPID level upgrade:
            # - does session ID remain the same? better assume it changes
            
            $self->dsl->redirect($self->dsl->session('__spid_sso_redirect'));
            $self->dsl->session('__spid_sso_redirect' => undef);
            
            $self->execute_plugin_hook('after_login');
        },
    );
    
    # Create a route for the logout endpoint.
    $self->app->add_route(
        method  => 'get',
        regexp  => $self->config->{logout_endpoint},
        code    => sub {
            # If we don't have an open SPID session, do nothing.
            return $self->dsl->redirect('/')
                if !$self->spid_session;
            
            $self->execute_plugin_hook('before_logout');
            
            # Craft the LogoutRequest.
            my $idp = $self->_spid->get_idp($self->spid_session->idp_id);
            my $logoutreq = $idp->logoutrequest(session => $self->spid_session);
            
            # Save the ID of the LogoutRequest so that we can check it in the response
            # in order to prevent forgery.
            $self->dsl->session('__spid_logoutreq_id' => $logoutreq->id);
            
            # Redirect user to the Identity Provider for logout.
            $self->dsl->redirect($logoutreq->redirect_url, 302);
        },
    );
    
    # Create a route for the SingleLogoutService endpoint.
    # This endpoint exposes a SingleLogoutService for our Service Provider, using
    # a HTTP-POST or HTTP-Redirect binding (it does not support SOAP).
    # Identity Providers can direct both LogoutRequest and LogoutResponse messages
    # to this endpoint.
    $self->app->add_route(
        method  => 'post',
        regexp  => $self->config->{slo_endpoint},
        code    => sub {
            if ($self->dsl->param('SAMLResponse') && $self->dsl->session('__spid_logoutreq_id')) {
                my $response = eval {
                    $self->_spid->parse_logoutresponse(
                        $self->dsl->param('SAMLResponse'),
                        $self->dsl->session('__spid_logoutreq_id'),
                    )
                };
                
                # Clear the ID of the outgoing LogoutRequest, regardless of whether we accept the response or not.
                $self->dsl->session('spid_logoutreq_id' => undef);
                
                if ($@) {
                    $self->dsl->warning("Bad LogoutResponse received: $@");
                    $self->dsl->status(400);
                    $self->dsl->content_type('text/plain');
                    return "Bad LogoutResponse: $@";
                }
                
                # Call the hook *before* clearing spid_session.
                $self->execute_plugin_hook('after_logout', $response->success);
                
                # Logout was successful! Clear the local session.
                $self->dsl->session('__spid_session' => undef);
                
                # Redirect user back to main page.
                $self->dsl->redirect('/');
            } elsif ($self->dsl->param('SAMLRequest')) {
                my $request = eval {
                    $spid->parse_logoutrequest($self->dsl->param('SAMLRequest'))
                };
                
                if ($@) {
                    $self->dsl->warning("Bad LogoutRequest received: $@");
                    $self->dsl->status(400);
                    $self->dsl->content_type('text/plain');
                    return "Bad LogoutRequest: $@";
                }
                
                # Now we should retrieve the local session corresponding to the SPID
                # session $request->session. However, since we are implementing a HTTP-POST
                # binding, this HTTP request comes from the user agent so the current Dancer
                # session is automatically the right one. This simplifies things a lot as
                # retrieving another session by SPID session ID is tricky without a more
                # complex architecture.
                my $status = 'success';
                if ($request->session eq $self->spid_session->session) {
                    # Call the hook *before* clearing spid_session.
                    $self->execute_plugin_hook('after_logout', 'success');
                    
                    $self->dsl->session('__spid_session' => undef);
                } else {
                    $status = 'partial';
                    $self->dsl->warning(
                        sprintf "SAML LogoutRequest session (%s) does not match current SPID session (%s)",
                            $request->session, $self->spid_session->session
                    );
                }
                
                # Craft a LogoutResponse and send it back to the Identity Provider.
                my $idp = $self->_spid->get_idp($request->issuer);
                my $response = $idp->logoutresponse(in_response_to => $request->id, status => $status);
    
                # Redirect user to the Identity Provider; it will continue handling the logout process.
                $self->dsl->redirect($response->redirect_url, 302);
            } else {
                $self->dsl->status(400);
            }
        },
    );
}

1;
