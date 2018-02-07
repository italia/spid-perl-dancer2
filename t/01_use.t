#!/usr/bin/env perl

use strict;
use warnings;

use Dancer2;
use Test::More tests => 1;

BEGIN {
    use_ok('Dancer2::Plugin::SPID');
}

__END__
