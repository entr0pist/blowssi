#!/usr/bin/perl -w

# blowssi - an mircryption/FiSH compatible irssi script
# Copyright (C) 2009 John Sennesael
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# -------------------- includes --------------------

# include ircBlowfish
use Crypt::ircBlowfish;

# include everything needed cbc+base64
use Crypt::CBC;
use MIME::Base64;

# include DH1080 needed
use Crypt::ircDH1080;

# include irssi stuff
use Irssi::Irc;
use Irssi;
use vars qw($VERSION %IRSSI);

# i don't trust myself
use strict;

# irssi package info
my $VERSION = "0.2.0";
my %IRSSI = (
    authors => 'John "Gothi[c]" Sennesael & Tanesha',
    contact => 'john@adminking.com',
    name => 'blowssi',
    description => 'Fish and mircryption compatible blowfish/cbc encryption (+dh1080 keyx)',
    license => 'GNU GPL v3',
    url => 'http://linkerror.com/blowssi.cgi'
);

# crypt enabled by default
my $docrypt = 1;
# associative array for channel->key
my %channels;
# get config file name
my $config_file = Irssi::get_irssi_dir()."/blowssi.conf";
# init blowfish object
my $blowfish = new Crypt::ircBlowfish;
# init dh1080 object
my $dh1080 = new Crypt::ircDH1080;
# Are we using cbc with keyx?
my $keyx_cbc = 0;

# https://github.com/shabble/irssi-docs/wiki/Guide#Use_Existing_Formats_for_Consistency
sub actually_printformat {
    my ($win, $level, $module, $format, @args) = @_;
    {
        local *CORE::GLOBAL::caller = sub {
            $module
        };

        $win->printformat($level, $format, @args);
    }
}

# blows up a key so it matches 56 bytes.
sub blowkey {
    # get params
    my $key = @_[0];
    my $orig_key = $key;

    # don't need to do anything if it's already big enough.
    if(length($key) >= 8) {
        return $key;
    }

    # keep adding the key to itself until it's larger than 8 bytes.
    while(length($key) < 8) {
        $key .= $key;
    }

    return $key;
}

# loads configuration
sub loadconf {
    # open config file
    my @conf;
    open(CONF, "<$config_file");

    # if config file does not exist, create it with default settings and exit.
    if(!( -f CONF)) {
        Irssi::print("\00305> $config_file not found, using default settings.");
        Irssi::print("\00305> Creating $config_file with default values.\n");
        close(CONF);
        open(CONF, ">$config_file");
        close(CONF);
        return 1;
    }

    # otherwise, proceed with reading config.
    @conf = <CONF>;
    close(CONF);
    my $current;

    foreach(@conf) {
        $current = $_;
        $current =~ s/\n//g; # remove newline

        if ($current ne '') {
            # config syntax is channel:key so split the string and get both.
            my $channel = (split(':', $current,2))[0]; 
            my $key = (split(':', $current,2))[1]; 

            # remove leading/trailing spaces
            $channel =~ s/^\s+//; 
            $channel =~ s/\s+$//; 
            $key =~ s/^\s+//; 
            $key =~ s/\s+$//; 

            # assign into array.
            $channels{$channel} = $key;
            Irssi:print("\00305> Loaded key for channel: $channel");
        }
    }

    Irssi::print("\00314- configuration file loaded.");
    Irssi::settings_add_bool('fish', 'use_colors', 1);
    return 1;
}

sub saveconf {
    # local declarations
    my ($channel,$key) = "";

    # open config file
    my @conf ;
    open(CONF, ">$config_file");

    # error check
    if(!( -f CONF)) {
        Irssi::print("\00305> Could not load config file: $config_file");
        close(CONF);
        return 1;
    }

    # write out config
    while(($channel,$key) = each(%channels)) {
        # don't save keyx keys (as the pub/priv key changes for each load)
        next if $key =~ /^keyx:/;

        if(($channel) && ($key)) {
            print CONF "$channel:$key\n";
        }
    }

    close(CONF);
}

sub delkey {
    # parse params
    my $channel = @_[0];

    # check user sanity
    if(!$channel) {
        Irssi::print("No channel specified. Syntax: /blowdel channel");
        return 1;
    }

    # delete from array
    delete($channels{$channel});

    # save to config
    saveconf();

    # print status
    Irssi::print("Key deleted, and no longer using encryption for $channel");
}

# calculates privmsg length.
sub irclen {
    my ($len, $curchan, $nick, $userhost) = @_;

    # calculate length of "PRIVMSG #blowtest :{blow} 4b7257724a ..." does not exceed
    # it may not exceed 511 bytes
    # result gets handled by caller.

    return $len + length($curchan) + length("PRIVMSG : ") + length($userhost) +
        1 + length($nick);
}

# turn on blowfish encryption
sub blowon {
    $docrypt = 1;
    Irssi::print("Blowfish encryption/decryption enabled");
}

# turn off blowfish encryption
sub blowoff {
    $docrypt = 0;
    Irssi::print("Blowfish encryption/decryption disabled");
}

# change encryption key
sub setkey {
    # parse params
    my $param = @_[0];
    my $channel = (split(' ', $param,2))[0];
    my $key = (split(' ', $param, 2))[1];

    unless($key && $channel) {
        Irssi::print("Current configuration..");

        foreach my $k (keys %channels) {
            Irssi::print("$k -> $channels{$k}");
        }

        return;
    }

    # check user sanity
    if(!$channel) {
        Irssi::print("Error: no channel specified. Syntax is /blowkey channel key");
        return 1;
    }

    if(!$key) {
        Irssi::print("Error: no key specified. Syntax is /blowkey channel key");
        return 1;
    }

    $channels{$channel} = $key;
    Irssi::print("Key for $channel set to $key");
    saveconf();
}

sub blowhelp {
    Irssi::print("$IRSSI{description}");
    Irssi::print("Commands");
    Irssi::print("---------------------------------------------------------------");
    Irssi::print("/blowhelp                       Show this help");
    Irssi::print("/blowon                         Turn blowfish back on.");
    Irssi::print("/blowoff                        Temporarily disable all blowfish.");
    Irssi::print("/blowkey <user|chan> <key>      Statically set key for a channel.");
    Irssi::print("/blowkeyx <user|chan>           Perform DH1080 key exchange with user.");
    Irssi::print("/blowdel <user|chan>            Remove key for user.");
    Irssi::print("");
}

sub keyx {
    # get params
    my ($user, $server, $winit) = @_;  

    # check user validity
    if(!$user) {
        Irssi::print("Error: no user specified. Syntax is /blowkeyx nickname");
        return 1;
    }

    # remove the old key (if any)
    delete $channels{$user};

    # get pubkey, store header...
    my $pubkey = $dh1080->public_key;  
    my $keyx_header="DH1080_INIT";
    
    $server->command("\^notice $user $keyx_header $pubkey");
    Irssi::print("KeyX started for $user.");
}

sub keyx_handler {
    # Get params.
    my ($event_type, $server, $message, $user) = @_;  
    chomp $message;

    # Uncomment for debug.
    # Irssi::print("$event_type keyx_finish on $message"); 
    my ($command, $peer_public) = $message =~ /DH1080_(INIT|FINISH) (.*)/i;

    return 1 unless $command && $peer_public;

    # handle it.
    my $secret = $dh1080->get_shared_secret($peer_public);

    if($secret) {
        if($command =~ /INIT/i) {      
            my $public = $dh1080->public_key;
            my $keyx_header = 'DH1080_FINISH';

            $server->command("\^notice $user $keyx_header $public");
            Irssi::print("Received key from $user -- sent back our pubkey.");
                } else {
            Irssi::print("Negotiated key with $user");
        }

        Irssi::print("\x0307WARNING\x03: this key exchange is not authenticated and is completely insecure.");
        Irssi::print('Use at your own risk. For details see:');
        Irssi::print('https://github.com/entr0pist/fakeircd/blob/rude/modules/Decrypt.py.disabled');

        Irssi::print("Debug: key = $secret");
        $channels{$user} = 'keyx:'.$secret;
    }

    # dont process this further
    Irssi::signal_stop();
}

# This function generates random strings of a given length
sub generate_random_string {
    my $length_of_randomstring = shift;# the length of 

    # the random string to generate
    my @chars = ('a'..'z', 'A'..'Z', '0'..'9', '_');
    my $random_string;

    foreach(1..$length_of_randomstring) {
        # rand @chars will generate a random 
        # number between 0 and scalar @chars
        $random_string .= $chars[rand @chars];
    }

    return $random_string;
}

# encrypt text
sub encrypt {
    # Uncomment to debug signals.
    #
    #my $n = 0;
    #foreach (@_)
    #{
    #  print "Debug encrypt: $n : $_"; 
    #  $n++;
    #}

    # Skip if crypt is disabled.
    if($docrypt == 0) {
        return 0;
    }

    # Holds parameters passed to function.
    my @params = @_;

    # Type of signal received. 
    my $event_type = @params[0];

    # Will hold Irssi server object.
    my $server;

    # Will hold channel name.
    my $channel = '';

    # Will hold message text.
    my $message = '';
    my $topic = 0;

    # Extract params for send_text events.
    if($event_type eq 'send_text') {
        # Get message text.
        $message = @params[1];
        chomp($message);

        # Get server object.
        $server = @params[2];

        # Get channel or nickname.    
        my $channel_object = @params[3];
        $channel = $channel_object->{name};
    # Extract params for send_command events.
    } elsif($event_type eq 'send_command') { 
        # Get command the user entered (eg: /me says hi)
        my $command_line = @params[1];

        # Get server object.
        $server = @params[2];

        # Get channel object.
        my $channel_object = @params[3];

        # We handle /me and /action commands, which will
        # be the first word in the $command_line string.
        my $command = (split(' ', $command_line))[0];

        # Target channel is the first param to the /action command.
        # Message to send is the 3rd param to /action, 2nd to /me.
        # Otherwise, for /me just get the channel from the active window.
        if($command =~ m/\/action/i) {
            $channel = (split(' ', $command_line,2))[1];
            $message = (split(' ', $command_line,3))[2];
        } elsif($command =~ m/\/me/i) {
            $channel = $channel_object->{name};
            $message = (split(' ', $command_line,2))[1];
        } elsif($command =~ m/\/topic/i) {
            $channel = $channel_object->{name};
            $message = (split(' ', $command_line,2))[1];
            $topic = 1;
        } else {
            # The only send_command's we handle here are /me and /action...
            return 0;
        }    
    # Extract params for everything else.
    } else {
        # Get server object.
        $server = @params[1];

        # Get message text.
        $message = @params[2];
        chomp($message);

        # Get channel or nickname target
        $channel = @params[3];
    }

    # Get the current active server address.
    my $current_server = $server->{address};

    # Get the user's nickname (own nickname).
    my $own_nick = $server->{nick};

    my $action = ($event_type eq 'send_command' and !$topic);

    # If there's no text to encrypt, then don't try.
    if(length($message) == 0) {
        return;
    }

    # if its dh1080_finish then skip encryption
    return if $message =~ /^DH1080_FINISH/;

    # skip if line starts with `
    if(substr($message, 0, 1) eq '`') {
        $message = substr($message,1);

        if($action) {
            $server->command("\^ACTION -$server->{tag} $channel $message");
            actually_printformat(Irssi::active_win, MSGLEVEL_ACTIONS, 'fe-common/irc',
                'own_action', $own_nick, $message);
        } elsif($event_type eq 'send_command' and $topic) {
            $server->command("TOPIC $channel $message");
        } else {
            $server->command("\^msg -$server->{tag} $channel $message");
            actually_printformat(Irssi::active_win, MSGLEVEL_PUBLIC, 'fe-common/core',
                'own_msg', $own_nick, $message);
        }

        Irssi::signal_stop();
        return 1;
    }

    # get key
    my $key = $channels{$channel};
    $key = substr($key, 5) if $key =~ /^keyx:/;

    # local declarations
    my $encrypted_message = '';

    # skip if no key
    if(!$key) {
        return 0;
    }   

    my $original = $message;

    if(length($message) < 280) {
        $message .= "\x00" x (280 - length($message));
    }

    if($action) {
        $message = "\x01ACTION $message\x01";
    }

    $message = substr($message, 0, 280);

    # ecb keys automatically upgraded to cbc. sucks to be you if you're still using ecb.
    if($key =~ /^(cbc|ecb):/) {
        $key = substr($key, 4);
    }

    # encrypt using cbc
    $key = blowkey($key); #expand >= 8 bytes.

    my $randomiv = generate_random_string(8);  
    my $cipher = Crypt::CBC->new(
        -key => $key,
        -cipher => 'Blowfish',
        -header => 'none',
        -literal_key => 0,
        -iv => $randomiv,
        -padding => 'null',
        -keysize => 56
    );

    $cipher->{literal_key} = 1; # hack around Crypt:CBC limitation/bug

    # my $cbc = $cipher->encrypt($randomiv . $message);
    my $cbc = $randomiv . $cipher->encrypt($message);

    # uncomment below for debug
    # Irssi::print("randomiv = $randomiv \n \$cbc = $cbc\n");

    $encrypted_message = '+OK *' . encode_base64($cbc);

    my $color = '';
    if(Irssi::settings_get_bool('use_colors')) {
        $color = "\00302";
    }

    # output line
    if($action) {
        actually_printformat(Irssi::active_win, MSGLEVEL_ACTIONS, 'fe-common/irc',
            'own_action', $own_nick, $color . $original);
        $server->command("\^msg -$server->{tag} $channel $encrypted_message");
    } elsif($event_type eq 'send_command' and $topic) {
        $server->command("TOPIC $channel $encrypted_message");
    } else {
        actually_printformat(Irssi::active_win, MSGLEVEL_PUBLIC, 'fe-common/core',
            'own_msg', $own_nick, $color . $original);
        $server->command("\^msg -$server->{tag} $channel $encrypted_message");
    }

    Irssi::signal_stop();
    return 1;
}

sub topic {
    my ($server, $msg, $nick) = @_;
    my ($user, $channel, $topic) = $msg =~ /^([^\s]+\s+)?([^\s]+)\s+:(.*)/;

    if(!$topic) {
        $topic = $channel;
        $channel = $user;
        $user = '';
    }

    my $key = $channels{$channel};
    if($key) {
        my $result = decrypt_msg($key, $topic);
        Irssi::signal_continue($server, "$user$channel :$result", $nick);
    }
}

# decrypt text
sub decrypt {
    # Uncomment to debug signals.
    #
    #my $n = 0;
    #foreach (@_)
    #{
    #  print "DEBUG decrypt: $n : $_"; 
    #  $n++;
    #}

    # Skip if crypt is disabled.
    if($docrypt == 0) {
        return 0;
    }

    # Holds parameters passed to function.
    my @params = @_;

    # Type of signal received. 
    my $event_type = @params[0];

    # Irssi server object.
    my $server = @params[1];

    # Don't decrypt own text.
    if($event_type =~ /own/) {
        return 0;
    }

    # Get message text, nickname of other party, hostmask of other party.
    my $message = @params[2];
    my $nick = @params[3];
    my $hostmask = @params[4];

    # Get channel.
    my $channel = @params[5];

    # Irssi::print("decrypt-params: " . join(", ", @params));

    # local declarations
    my $key = $channels{$channel};

    # fixup for private messages
    $key = $channels{$nick} if $channel !~ /^#/;

    # fixup for key exchange keys.
    $key = substr($key, 5) if $key =~ /^keyx:/;

    # skip if there's no key for channel
    if(!$key) {
        return 0;
    }

    my $result = decrypt_msg($key, $message);

    my $color = '';
    if($result ne $message && Irssi::settings_get_bool('use_colors')) {
        $color = "\00303"; 
    }

    # output result
    if(length($result)) { 
        if($event_type eq 'message_action' or $result =~ /^\x01ACTION (.*)\x01?$/) {
            $channel = $nick if $channel !~ /^#/;

            my $window = $server->window_item_find($channel);
            if(!$window) {
                $server->command("QUERY $channel");
                $window = $server->window_item_find($channel);
            }

            $result =~ s/^\x01ACTION ([^\x01]+)\x01?$/\1/;

            actually_printformat($window, MSGLEVEL_ACTIONS, 'fe-common/irc',
                'action_public', $nick, $color . $result);
        } elsif($event_type eq 'message_private') {
            my $window = $server->window_item_find($nick);
            if(!$window) {
                $server->command("QUERY $nick");
                $window = $server->window_item_find($nick);
            }

            actually_printformat($window, MSGLEVEL_MSGS, 'fe-common/core', 'pubmsg', $nick,
                $color . $result);
        } else {
            actually_printformat($server->window_item_find($channel), MSGLEVEL_PUBLIC,
                'fe-common/core', 'pubmsg', $nick, $color . $result);
        }
    } else {
        return 0;
    }

    Irssi::signal_stop();
    return 1;
}

sub decrypt_msg {
    my ($key, $message) = @_;

    my $result = '';

    # skip encryption if the message isn't prefixed with an encryption trigger.
    if($message !~ /^(\[[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\] )?\+OK \*.*/) {
        return $message;
    }

    if($message =~ /^\[/) {
        $message = substr($message, 11);
    }

    $message = substr($message, 5);
    if($key =~ /^(ecb|cbc):/) {
        $key = substr($key, 4);
    }
    
    # base64 decode the rest
    $message = decode_base64($message);

    # get the IV (first 8 bytes) and remove it from data;
    my $randomiv = substr($message, 0, 8);
    $message = substr($message, 8);

    # make sure key > 8 bytes.
    $key = blowkey($key);

    my $cipher = Crypt::CBC->new(
        -key => $key,
        -cipher => 'Blowfish',
        -header => 'none',
        -literal_key => 0,
        -padding => 'null',
        -iv => $randomiv
    );

    $cipher->{literal_key} = 1; # hack around Crypt::CBC limitation/bug
    $result = $cipher->decrypt($message);

    chomp $result;
    return $result;
}

# dcc proxy function because params for dcc messages are different
sub dcc {
    my ($server, $data) = @_ ;
    encrypt($server, $data, $server->{nick}, undef);
}

# ----------------- main program -------------------

# load config
loadconf();

# inform user of stuff
Irssi::print("blowssi script $VERSION loaded\n");

# register irssi commands
Irssi::command_bind("blowon", "blowon");
Irssi::command_bind("blowoff", "blowoff");
Irssi::command_bind("blowkey", "setkey");
Irssi::command_bind("blowdel", "delkey");
Irssi::command_bind("blowkeyx", "keyx");
Irssi::command_bind("blowhelp", "blowhelp");

Irssi::signal_add("send text", sub { 
    my @e = @_;

    foreach(unpack('(A280)*', @e[0])) {
        @e[0] = $_;
        encrypt 'send_text' => @e;
    }
});

Irssi::signal_add("send command", sub {
    encrypt 'send_command' => @_
});

Irssi::signal_add_first("event topic", "topic");
Irssi::signal_add_first("event 331", "topic");
Irssi::signal_add_first("event 332", "topic");

# register irssi signals
Irssi::signal_add_first {
    'message private' => sub {
        decrypt 'message_private' => @_
    },
    'message public' =>  sub {
        decrypt 'message_public' => @_
    },    
    'message irc action' => sub {
        decrypt 'message_action' => @_
    },
    'message irc notice' => sub {
        decrypt 'message_notice' => @_
    },
    'message irc own_notice' => sub {
        encrypt 'message_own_notice' => @_
    },
    'message irc ctcp' => sub {
        decrypt 'message_ctcp' => @_
    },
    'message irc own_ctcp' => sub {
        encrypt 'message_own_ctcp' => @_
    }
};

# dh1080 handling
Irssi::signal_add_first {
    'message irc notice' => sub {
        keyx_handler 'message_notice' => @_
    }
};
