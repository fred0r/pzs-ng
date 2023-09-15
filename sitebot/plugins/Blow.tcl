################################################################################
# ngBot - Blow plugin v0.4 original concept by poci                            #
################################################################################
# Support eggdrop 1.8.4 and higher, eggdrop 1.9.x and higher, with cypher CBC
# and ECB. Key exchange with DH1080_tcl, FiSH-irssi or weechat-fish plugin.
#
# These peeps have my thanks: ZarTek-Creole, comp :) neoxed, meij, god-emper,
# al gore and jesus
#
# FEATURES:
# by ZarTek-Creole:
# - CBC encryption per default (best security)
# - Use native blowfish encryption of eggdrop (blowfish module)
# - supports "putnow" command
# - replace "![IsTrue ]" per "[IsFalse ]"
# - split configuration to a separate file (Blow.conf)
# - replace raw per rawt (because is obselet): If the proc returns 1, Eggdrop will not process the line any further,
#    to include not being processed by a RAW bind (this could cause unexpected behavior in some cases). As of 1.9.0,
#    it is recommended to use the RAWT bind instead of the RAW bind.
# - support mcps prefix (mircryption)
#    https://github.com/flakes/mirc_fish_10/blob/e0546fec2c33a5b6abd8fc81eb00bb5f55899440/fish_10/src/fish-main.cpp#L153
# - remove old Blow::unencryptedIncomingHandler and Blow::uncryptedIncomingHandler replaced by Blow::incomingRawtPRIVMSG
# - remove old bind raw, "+ok" and replace by rawt (see above)
#
# by comp :)
# - split lines if they become too long
# - enable/disable key exchange, or just allow it for a selected group of people
# - prevent the bot from sending unencrypted PRIVMSG/NOTICE.
# - set/read topic from irc (!topic) or from site ('site topic #chan topic')
# - integrates perfectly with pzs-ng and NickDb
# - CBC support (chan ofc and keyx), needs eggdrop 1.8.2+
# - more alternatives besides FiSH DH1080_tcl: FiSH-irssi or weechat-fish plugin
#
# INSTALLATION:
#
# 1. Edit the plugin theme (Blow.zpt) for the *TOPIC announces.
#
# 2. Add the following to your glftpd.conf:
#      site_cmd        TOPIC           EXEC            /bin/ng-topic.sh
#      custom-topic 1 =siteops !*
#
# 3. Rename blow.conf.example to blow.conf and edit it.
#
################################################################################

namespace eval ::ngBot::plugin::Blow {
  variable ns                   [namespace current]
  variable np                   [namespace qualifiers [namespace parent]]
  variable blowkey
  variable blowversion          "20230521"
  variable events               [list "SETTOPIC" "GETTOPIC"]
  variable scriptFile           [info script]
  variable putName              [list "quick" "serv" "help" "now"]

  interp alias {} IsTrue {} string is true -strict
  interp alias {} IsFalse {} string is false -strict

  ####
  # Blow::Debug
  #
  # Pretty self-explanatory
  #
  proc Debug {msg} {
    variable np
    variable ${np}::debugmode
    if {[IsTrue [set ${np}::debugmode]]} {
      putlog "\[ngBot\] Blow :: $msg"
    }
  }

  ####
  # Blow::Error
  #
  # Pretty self-explanatory
  #
  proc Error {error} {
    putlog "\[ngBot\] Blow Error :: $error"
  }

  ####
  # Blow::SetTopic
  #
  # Sets a new topic for a channel
  #
  proc SetTopic {channel topic} {
    variable ns
    if {[IsTrue [${ns}::matchChan $channel]]} {
      putquick "TOPIC $channel :$topic"
      return True
    }
    return False
  }

  ####
  # Blow::GetTopic
  #
  # Returns the current topic for $channel
  #

  proc GetTopic {channel} {
    variable ns
    set topic                   [topic $channel]
    set key                     [${ns}::getKey $channel]
    if {[string equal $key ""]} { return $topic }

    if {[IsTrue [${ns}::matchChan $channel]] && [string equal [lindex $topic 0] "+OK"]} {
      set topic                 [decryptMsg $channel [lindex $topic 1]]
    }
    return $topic
  }

  ####
  # Blow::breakLine
  #
  # Breaks input into parts
  #
  proc breakLine {line lineArr} {
    variable ns
    variable maxLength 5
    variable splitChar
    upvar $lineArr broken
    set length                  [string length $line]

    set pos                     0
    ## round UP
    set runs                    [expr round([expr $length/$maxLength]+0.5)]
    ## length of each new line
    set partSize                [expr round([expr $length/$runs]+0.5)]
    for {set i 0} {$i<$runs} {incr i} {
      ## heavy stuff
      set newPart               [string range $line $pos [expr $pos + $partSize]]

      set broken($i)            [string range $line $pos [expr [string last " " $newPart]+$pos]]
      set pos                   [string last " " [string range $line $pos [expr $pos + $partSize]]];
      incr pos
    }
    return True
  }

  ####
  # Blow::isMsgEncrypted
  #
  # Call this function to see if a message is encrypted
  #
  proc isMsgEncrypted {} {
    global blowEncryptedMessage
    if {[info exists blowEncryptedMessage]} {return True}
    return False
  }

  ####
  # Blow::reEscape
  #
  # Escapes all non-alfanumeric for use in a regexp
  #
  proc reEscape {str} {
    regsub -all {\W} $str {\\&}
  }

  ####
  # Blow::getKey
  #
  # Returns key associated with $target
  #
  ####
  # Blow::getKey
  #
  # Returns key associated with $target
  #
  proc getKey {target} {
    variable keyx
    variable blowkey
    variable mainChan

    set names                   [array names blowkey]
    # Old configs had example blowkeys as blowkey("#chan1") etc, accommodate for this.
    if {[set index [lsearch -regexp $names "(?i)^\"?[reEscape $target]\"?$"]] == -1} {
      if {![string equal $mainChan ""] && [info exists blowkey($mainChan)] && ![IsTrue $keyx]} {
        return $blowkey($mainChan)
      }

      return
    }

    return $blowkey([lindex $names $index])
  }

  ####
  # Blow::matchChan
  #
  # checks if $chan is defined in the blowkey array
  #
  proc matchChan {target} {
    variable blowkey
    # Old configs had example blowkeys as blowkey("#chan1") etc, accommodate for this.
    if {[lsearch -regexp [array names blowkey] "(?i)^\"?[reEscape $target]\"?$"] != -1} { return 1 }

    return 0
  }

  ####
  # Blow::encryptThis
  #
  # checks if the outgoing command matches PRIVMSG or NOTICE
  #
  proc encryptThis {text} {
    foreach type [list "PRIVMSG " "NOTICE " "TOPIC "] {
      if {[string equal -nocase -length [string length $type] $text $type]} {
        return 1
      }
    }
    return 0
  }

  # check is an trusted user is sending the command
  proc is_trustedusers {} {
    variable trustedUsers
    if {[info exists trustedUsers]} {
      if {[regexp -- {^([*]|)$} $trustedUsers]} { return 1 }
    }
    return 0
  }

  proc is_topicusers {} {
    variable topicUsers
    if {[info exists topicUsers]} {
      if {[regexp -- {^([*]|)$} $topicUsers]} { return 1 }
    }

    return 0
  }

  ####
  # Blow::keyx_nick
  #
  # Called on nick events. Moves the blowkey from the old nickname to the new nickname, if one exists.
  #
  proc keyx_nick {nick host hand chan newnick} {
    variable blowkey
    variable keyxinit
    variable keyxtimer
    variable keyxqueue
    foreach var [list "blowkey" "keyxinit" "keyxtimer" "keyxqueue"] {
      if {[info exists $var($nick)]} {
        set $var($newnick)      $var($nick)
        unset $var($nick)
      }
    }
  }

  proc keyx_generate {target name_public {name_private ""}} {
    variable fileBlowSO
    variable blowinit
    variable fileFishPY
    variable keyxCbc

    if {[IsFalse [info exists blowinit($target)]]} {
      upvar $name_public key_public
      if {[IsFalse [string equal $name_private ""]]} { upvar $name_private key_private }

      ## IMPORTANT: the 2 variables should be at least 200 bytes each!
      ## You might run into a crash, if they are too small!
      set key_private           [string repeat x 300]
      set key_public            [string repeat x 300]

      # Overwrites the variables with the generated values.
      if {[IsFalse [string equal $fileBlowSO ""]]} {
        DH1080gen $key_private $key_public
        # remove null termination char from c string
        regsub -all {\000.*} $key_public "" key_public
      } elseif {[IsFalse [string equal $fileFishPY ""]]} {
        lassign [exec $fileFishPY DH1080gen $key_private $key_public] key_private key_public
      }
      if {[IsTrue $keyxCbc]} {
        append key_public       " CBC"
      }
      # Only set blowinit if we're initiating the handshake.

      if {[IsFalse [string equal $name_private ""]]} {
        set blowinit($target)   $key_private
      }
      return 1
    }
    return 0
  }

  proc keyx_init {target} {
    variable ns
    variable np

    if {[${ns}::keyx_generate $target my_key_pub]} {
      putquick2 "NOTICE $target :DH1080_INIT $my_key_pub"
      ${ns}::Debug "keyx_init: Sending DH1080 public key to $target."
    }
  }

  proc keyx_bind {nick host handle text dest} {
    variable np
    variable ns
    variable keyx
    variable keyxUsers
    variable fileBlowSO
    variable blowkey
    variable blowinit
    variable fileFishPY
    variable keyxCbc
    variable keyxCbcForce

    if {[IsFalse $keyx]} {
      ${ns}::Debug "Key exchange is disabled!"
      return
    }

    if {[IsFalse [is_trustedusers]]} {
      set ftp_user              [${ns}::GetFtpUser $nick]
      if {[IsFalse [${ns}::GetInfo $ftp_user ftp_group ftp_flags]]} {
        return
      }
      if {[IsFalse [${np}::rightscheck $keyxUsers $ftp_user $ftp_group $ftp_flags]]} {
        return
      }
    }

    set text                    [split $text]
    set len                     [string length [lindex $text 1]]
    variable mode_msg           ""
    if {
      [string match [lindex $text end] "CBC"]                               || \
        [lsearch {DH1080_INIT_CBC DH1080_FINISH_CBC} [string toupper [lindex $text 0]]] != -1
    } {
      variable mode_msg         " (CBC mode)"
    } elseif {[IsTrue $keyxCbcForce]} {
      return
    }

    switch -- [string toupper [lindex $text 0]] {
      DH1080_INIT {
        if { ($len > 178) || ($len < 182) } {
          if {[${ns}::keyx_generate $nick my_key_pub my_key_prv]} {
            putquick2 "NOTICE $nick :DH1080_FINISH $my_key_pub"
            set his_key_pub     [lindex $text 1]

            if {[IsFalse [string equal $fileBlowSO ""]]} {
              DH1080comp $my_key_prv $his_key_pub
            } elseif {[IsFalse [string equal $fileFishPY ""]]} {
              set his_key_pub   [exec $fileFishPY DH1080comp $my_key_prv $his_key_pub]
            }
            set blowkey($nick)  $his_key_pub
            ${ns}::Debug "keyx_bind: Received DH1080 public key from $nick. Sending DH1080 public key to $nick${mode_msg}."

            ${ns}::keyx_queue_flush $nick

            return 1
          }
        }
      }
      DH1080_FINISH {
        if { ($len > 178) || ($len < 182) } {
          if {[info exists blowinit($nick)]} {
            set his_key_pub     [lindex $text 1]
            if {[IsFalse [string equal $fileBlowSO ""]} {
              DH1080comp $blowinit($nick) $his_key_pub
            } elseif {[IsFalse [string equal $fileFishPY ""]]} {
              set his_key_pub   [exec $fileFishPY DH1080comp $blowinit($nick) $his_key_pub]
            }
            set blowkey($nick)  $his_key_pub
            unset blowinit($nick)
            ${ns}::Debug "keyx_bind: Received DH1080 public key from $nick${mode_msg}."

            ${ns}::keyx_queue_flush $nick

            return 1
          }
        }
      }
      DH1024_INIT {
        # NOT SUPPORTED!
      }
      DH1024_FINISH {
        # NOT SUPPORTED!
      }
    }
  }

  proc keyx_queue {target type command text {option ""}} {
    variable ns
    variable keyxtimer
    variable keyxqueue
    variable keyxTimeout

    # Clean up the queue variable if the keyx handshake isnt completed
    # within 120 seconds.
    if {[IsFalse [info exists keyxtimer($target)]]} {
      set timeout               [expr { [string is integer $keyxTimeout] ? $keyxTimeout : 120 }]
      set keyxtimer($target)    [utimer $timeout [list ${ns}::keyx_queue_delete $target]]
    }

    lappend keyxqueue($target) $type $command $text $option
  }

  proc keyx_queue_delete {target} {
    variable keyxqueue
    variable keyxtimer

    catch {killutimer $keyxtimer($target)}
    catch {unset keyxtimer($target)}
    catch {unset keyxqueue($target)}
  }

  # Decrypt a message with the good cypher
  proc decryptMsg {target message} {
    variable ns
    set data                    [${ns}::getKey $target]
    set mode                    [keyToEncryptMode $data]
    set key                     [getKeyWithoutEncryptMode $data]
    return [decrypt $mode:$key $message]
  }
  proc encryptMsg {target message} {
    variable ns
    set data                    [${ns}::getKey $target]
    set mode                    [keyToEncryptMode $data]
    set key                     [getKeyWithoutEncryptMode $data]
    return [encrypt $mode:$key [string trim $message]]
  }

  proc keyToEncryptMode { key } {
    # By ZarTek
    # key possible values:
    # cbc:blowfish
    # ebc:blowfish
    # blowfish
    # check if 4 element is : or not
    if { [IsFalse [string equal [string index $key 3] ":"]] } {
      # if not specified mode, set default mode cbc
      return "cbc"
    }
    # if specified mode, return mode
    return [string tolower [string range $key 0 3]]
  }
  proc getKeyWithoutEncryptMode { key } {
    # By ZarTek
    # key possible values:
    # cbc:blowfish
    # ebc:blowfish
    # blowfish
    # check if 4 element is : or not
    if { [IsFalse [string equal [string index $key 3] ":"]] } {
      return $key
    }
    return [string range $key 5 end]
  }
  proc keyx_queue_flush {target} {
    variable ns
    variable blowkey
    variable keyxqueue

    if {[IsFalse [info exists keyxqueue($target)]] || [IsFalse [info exists blowkey($target)]]} { return }

    foreach {type command text option} $keyxqueue($target) {
      ${ns}::put_encrypted $target $type $command $text $blowkey($target) $option
    }

    ${ns}::keyx_queue_delete $target
  }

  ####
  # Blow::IrcTopic
  #
  # Wraps up the arguments of !topic nicely and shows topic OR sends new topic to chan
  proc IrcTopic {nick host handle channel text} {
    variable ns
    variable np
    variable topicUsers
    if {[string equal $text ""] } {
      set topic                 [${ns}::GetTopic $channel]
      ${np}::sndall GETTOPIC DEFAULT [${np}::ng_format "GETTOPIC" "DEFAULT" \"$topic\"]
    } else {
      if {[${ns}::is_topicusers]} {
        if {[IsTrue [${ns}::SetTopic $channel "$text"]]} {
          ${ns}::Debug "Topic for $channel set: $text"
        }

        return
      }
      set ftpUser               [${ns}::GetFtpUser $nick]
      if {[${ns}::GetInfo $ftpUser ftpGroup ftpFlags] && [${np}::rightscheck $topicUsers $ftpUser $ftpGroup $ftpFlags] && [IsTrue [${ns}::SetTopic $channel "$text"]]} {
        ${ns}::Debug "Topic for $channel set: $text"
      } else {
        ${ns}::Debug "Unauthorized user: $nick"
      }
    }
  }
  ####
  # Blow::incomingRawtPRIVMSG
  #
  # Takes care of incoming messages and checks if they are bound to any command
  #
  proc incomingRawtPRIVMSG {from type text tag} {
    variable ns
    variable keyx
    variable plainTextSentence
    variable blowinit
    variable blowkey
    variable plainTextWarningMsg
    set target                  [lindex $text 0]
    set key                     [${ns}::getKey $target]
    set message                 [lrange $text 1 end]
    set mprefix                 [lindex $message 0]
    set mfished                 [lindex $message 1]
    # Find out if its a PUB or MSG bind.
    if {[set isPublicMessage         [string equal [string index $target 0] "#"]]} {
      # From the eggdrop Tcl manual: "PUBM binds are processed before PUB binds."
      set bind                  { "pubm" "pub" }
    } else {
      # From the eggdrop Tcl manual: "MSGM binds are processed before MSG binds."
      set bind                  { "msgm" "msg" }
    }
    set nick                    [lindex [split $from !] 0]
    set userHost                [lindex [split $from !] 1]
    set userName                [lindex [split $userHost @] 0]
    set uhost                   [lindex [split $userHost @] 1]

    # target is encrypted, check if message is encrypted too
    # CBC -> :+OK *WFzca/K5acH/q3r.Q1Pj8Jm.u3kUC/UuD7l0k1mgV0DyN310
    # ECB -> :+OK WFzca/K5acH/q3r.Q1Pj8Jm.u3kUC/UuD7l0k1mgV0DyN310
    if { [string equal $mprefix ":+OK"] } {
      # message is encrypted, decrypt it
      set isEncryptedText       1
      # mcps -> :mcps WFzca/K5acH/q3r.Q1Pj8Jm.u3kUC/UuD7l0k1mgV0DyN310
    } elseif { [string equal $mprefix ":mcps"] } {
      # message is encrypted, decrypt it
      set isEncryptedText       1
      # CBC -> *WFzca/K5acH/q3r.Q1Pj8Jm.u3kUC/UuD7l0k1mgV0DyN310
    } elseif { [string equal [string index $mprefix 1] "*"]} {
      # message is encrypted, decrypt it
      set isEncryptedText       1
      set mfished              $mprefix
      set mprefix              ""
    } else {
      # message is not encrypted, check if it's a plain text sentence
      set isEncryptedText       0
    }

    # If we received an encrypted private message, don't have a key
    # for the user and it was trigger by a MSG bind, reinit a key exchange.
    if {[IsTrue $keyx] && [IsFalse [${ns}::matchChan $target]] && !$isPublicMessage} {
      if { $plainTextSentence > 0 && [IsFalse $isEncryptedText] } {
        putserv2 "PRIVMSG $target :[format $plainTextWarningMsg [keyToEncryptMode $key]]"
        return 1
      }
      if {[IsFalse [info exists blowinit($target)]]} {
        ${ns}::keyx_init $target

        putserv2 "PRIVMSG $target :Unable to decrypt last message, redid key exchange. Please try again."
        return 1
      }
    }
    if { $key eq "" } {
      # no key, no encryption for target
      # no need to decrypt, stop here
      return 0
    }
    # i have a key, and user talk without encryption
    if { $plainTextSentence > 0 && [IsFalse $isEncryptedText] } {
      if {[IsTrue [${ns}::matchChan $target]] && $isPublicMessage} {
        if {$plainTextSentence == 2} {
          putserv2 "PRIVMSG $target :$nick: [format $plainTextWarningMsg [keyToEncryptMode $key]]"
        }
        if {$plainTextSentence == 3 || $plainTextSentence == 4} {
          if {[botisop $target] && [onchan $nick $target]} {
            putkick $target $nick [format $plainTextWarningMsg [keyToEncryptMode $key]]
          }
        }
        if {$plainTextSentence == 4} {
          variable userHost [getchanhost $nick]
          if {[string equal "" $userHost]} {
            set userHost        "*@*"
          }
          newchanban $target $nick!$userHost $nick [format $plainTextWarningMsg [keyToEncryptMode $key]]
        }
        return 1
      }
    }
    # i have a key, and user talk with encryption
    set tmp                     [decryptMsg $target $mfished]
    # From the eggdrop server help: "exclusive-binds:
    #   This setting configures PUBM and MSGM binds to be exclusive of PUB and MSG binds."
    set mExecuted               0
    ##${ns}::Debug "received encrypted message: $tmp"
    foreach bindtype $bind {
      foreach item [binds $bindtype] {
        if {[string equal [lindex $item 2] "+OK"] || [string equal [lindex $item 2] "mcps"]} {
          continue
        }
        # ZarTek Information:
        # - I know that there are bugs with matchattr in some versions of eggdrop.
        # -"-|-" is for me a bad practice, because it can have commands intended for specific users (administrator of
        #    the eggdrop) even if it is too often used.
        # References:
        # - https://github.com/eggheads/eggdrop/issues?q=matchattr
        # - https://docs.eggheads.org/using/tcl-commands.html#flag-masks
        # if {[IsFalse [string equal [lindex $item 1] "-|-"]] && [IsFalse [matchattr $nick [lindex $item 1] $target]]} { continue }
        set blowEncryptedMessage 1
        set lastbind            [lindex $item 2]
        set targchan            "*"
        if {[string equal "$bindtype" "pubm"]} {
          set targchan          [lindex "$lastbind" 0]
          if {[string equal "$targchan" "%"]} {
            set targchan        "*"
          }
          set lastbind          [lrange "$lastbind" 1 end]
        }
        ## execute bound proc
        if {[string match "$targchan" "$target"]} {
          if {
            ([string equal "$bindtype" "pubm"] || [string equal "$bindtype" "msgm"]) && \
              [regexp "[string map {\\* .* \\? . \\% \\S* \\~ \\s+} "[reEscape "[join $lastbind]"]"]" "[join $tmp]"]
          } {
            if {[info exists exclusive-binds] && ${::exclusive-binds}} {
              set mExecuted     1
            }
            if {$isPublicMessage} {
              eval [lindex $item 4] \$nick \$uhost * \$target {[join $tmp]}
            } else {
              eval [lindex $item 4] \$nick \$uhost * {[join $tmp]}
            }
          } elseif {!$mExecuted && [string equal "$lastbind" [lindex $tmp 0]]} {
            # Use "eval" to expand the callback script, for example:
            # bind pub -|- !something [list PubCommand MyEvent]
            # proc PubCommand {event nick uhost handle chan text} {...}
            if {$isPublicMessage} {
              eval [lindex $item 4] \$nick \$uhost * \$target {[join [lrange $tmp 1 end]]}
            } else {
              eval [lindex $item 4] \$nick \$uhost * {[join [lrange $tmp 1 end]]}
            }
          }
        }
        unset blowEncryptedMessage
      }
    }
    return 1
  }

  ####
  # Blow::GetInfo
  #
  # gets $group and $flags from the userfile
  #
  proc GetInfo {ftpUser groupVar flagsVar} {
    variable ns
    variable np
    variable ${np}::location
    upvar $groupVar group $flagsVar flags

    set file                    "$location(USERS)/$ftpUser"
    # Linux will give an error if you open a directory and try to read from it.
    if {[IsFalse [file isfile $file]]} {
      ${ns}::Error "Invalid user file for \"$ftpUser\" ($file)."
      return 0
    }

    set group                   "";
    set flags                   ""
    if {[catch {set handle [open $file r]} error] == 0} {
      set data                  [read $handle]
      close $handle
      foreach line [split $data "\n"] {
        switch -exact -- [lindex $line 0] {
          "FLAGS" {
            set flags           [lindex $line 1]
          }
          "GROUP" {
            set group           [lindex $line 1]
          }
        }
      }
      return 1
    } else {
      ${ns}::Error "Unable to open user file for \"$ftpUser\" ($error)."
      return 0
    }
  }

  # Outgoing messages
  proc put_bind {type text {option ""}} {
    variable ns
    variable keyx
    variable blowinit
    variable maxLength
    variable allowUnencrypted

    # Only allow valid procs to be called.
    if {[lsearch -regexp [list "quick" "serv" "help" "now"] "(?i)^$type$"] == -1} { return }

    set ltext                   [split $text]
    set target                  [lindex $ltext 1]
    set key                     [${ns}::getKey $target]

    # Key exchange is turned on, message is not being sent to a channel,
    # we're supposed to encrypt this type of message and there isnt
    # already already a key for this target.
    if {[IsTrue $keyx] && [regexp -- {^[^&#]} $target] && \
      [IsTrue [${ns}::encryptThis $text]] && [IsFalse [${ns}::matchChan $target]]} {
        # Initiate if we haven't already.
        if {[IsFalse [info exists blowinit($target)]]} {
          # Will set blowinit($target)
          ${ns}::keyx_init $target
      }
    }

    if {
      ([IsTrue [${ns}::encryptThis $text]] && \
        [IsFalse [string equal $key ""]])                                   || \
        [info exists blowinit($target)]
    } {
      if {
        [IsFalse [string equal $key ""]]                                    || \
          [info exists blowinit($target)]
      } {
        ## we have to encrypt this
        set command             [lindex $ltext 0]

        set pos                 [string first : $text]
        if {$pos == -1 || [string equal $pos " "]} {
          ${ns}::Error "BOGUS MESSAGE"
          return
        }
        set message             [string range $text [incr pos] end]

        if {[string length $message] > $maxLength} {
          ## start splitting
          ${ns}::breakLine $message lineArr
          foreach {{} msg} [array get lineArr] {
            put${type}2 "$command $target :+OK [encryptMsg $target $message]"
          }
          return 1
        } else {
          ## message is short enough to fit on one line
          put${type}2 "$command $target :+OK [encryptMsg $target $message]"
          return 1
        }
      } elseif {[IsTrue $allowUnencrypted]} {
        ## message for undefined channel
        ${ns}::put_unencrypted $type $text $option
      }
    } else {
      ## we're sending a command (MODE/JOIN/WHATEVER)
      ${ns}::put_unencrypted $type $text $option
    }
    return 1
  }

  proc put_unencrypted {type text {option ""}} {
    if {[IsTrue [string equal $option ""]]} {
      put${type}2 $text
    } else {
      put${type}2 $text $option
    }
    return 1
  }

  proc put_encrypted {target type command text key {option ""}} {
    variable ns
    if {![string equal $key ""]} {
      if {[IsTrue [string equal $option ""]]} {
        put${type}2 "$command $target :+OK [encryptMsg $target $text]"
        return 1
      } else {
        put${type}2 "$command $target :+OK [encryptMsg $target $text]" $option
        return 1
      }
    } else {
      ${ns}::keyx_queue $target $type $command $text $option
    }
  }

  ####
  # Blow::LogEvent
  #
  # Called on logevents (facilitated by ngBot)
  #
  proc LogEvent {event section logData} {
    variable ns
    ${ns}::Debug "LogEvent {$event $section $logData} called"
    if {![string equal "SETTOPIC" $event]} {return 1}
    set channel                 [lindex $logData 0]
    set topic                   [lindex $logData 1]
    if {[IsFalse [${ns}::SetTopic $channel $topic]]} {
      ${ns}::Debug "Unable to set topic"
    }
    return 1
  }

  ####
  # Blow::Init
  #
  # Called on initialization
  #
  proc init {args} {
    variable ns
    variable np
    variable keyx
    variable fileBlowSO
    variable fileFishPY
    variable events
    variable topicUsers
    variable trustedUsers
    variable allowUnencrypted
    variable scriptFile
    variable blowversion
    variable topictrigger
    variable putName
    variable ${np}::cmdpre
    variable ${np}::variables
    variable ${np}::disable
    variable ${np}::msgtypes
    variable ${np}::precommand
    variable theme_file         [file normalize "[pwd]/[file rootname $scriptFile].zpt"]
    variable config_file        [file normalize "[pwd]/[file rootname $scriptFile].cfg"]
    variable aliases            [interp aliases]
    set variables(SETTOPIC)     "%channel %topic"
    set variables(GETTOPIC)     "%topic"
    if {[catch {source $config_file} error]} {
      ${ns}::Error "Unable to source config file: $error"
      return -code -1
    }
    # Check for required packages
    if {[catch {package require eggdrop 1.8.4} error]} {
      ${ns}::Error "Blow.tcl requires eggdrop version 1.8.4 or higher to work: $error"
      return -code -1
    }
    if {[IsFalse [string equal $fileFishPY ""]]} {
      if {[IsFalse [file exists $fileFishPY]]} {
        ${ns}::Error "Unable to find file: $fileFishPY"
        return -code -1
      }
      # check if executable
      if {[IsFalse [file executable $fileFishPY]]} {
        ${ns}::Error "File $fileFishPY is not executable, chmod +x it?"
        return -code -1
      }
    }

    if {[IsFalse [string equal $fileBlowSO ""]]} {
      if {[IsFalse [file exists $fileBlowSO]]} {
        ${ns}::Error "Unable to find file: $fileBlowSO"
        return -code -1
      }
      # check if executable
      if {[IsFalse [file executable $fileBlowSO]]} {
        ${ns}::Error "File $fileBlowSO is not executable, chmod +x it?"
        return -code -1
      }
    }



    if {[IsTrue $keyx]} {
      if {[IsFalse [string equal $fileBlowSO ""]]} {
        if {[catch {load $fileBlowSO} error]} {
          ${ns}::Error $error
          return -code -1
        }
      } elseif {[IsFalse [string equal $fileFishPY ""]]} {
        if {[IsFalse [file exists $fileFishPY]]} {
          ${ns}::Error "$fileFishPY does not exist"
          return -code -1
        }
      } elseif {[string equal $fileBlowSO ""] && [string equal $fileFishPY ""]} {
        ${ns}::Error "No DH key exchange method set"
        return -code -1
      }
    }


    set aliases [interp aliases]
    foreach cmd {putquick putserv puthelp putnow} {
      if {[lsearch $aliases $cmd] != -1 || [catch {info args $cmd}] == 0 || [info commands $cmd] == ""} {
        ${ns}::Error "Output procs have already been renamed. Make sure no other blowfish scripts are loaded and \002.restart\002."
        return -code -1
      }
    }

    ## Intercept putquick, putserv and puthelp, and replace it with our own version
    catch {rename ::putquick ::putquick2}
    catch {rename ::putserv ::putserv2}
    catch {rename ::puthelp ::puthelp2}
    catch {rename ::putnow ::putnow2}

    interp alias {} putquick {} ${ns}::put_bind "quick"
    interp alias {} putserv {} ${ns}::put_bind "serv"
    interp alias {} puthelp {} ${ns}::put_bind "help"
    interp alias {} putnow {} ${ns}::put_bind "now"


    if {[file isfile $theme_file]} {
      ${np}::loadtheme $theme_file true
    }

    ## Register the event handler.
    foreach event $events {
      lappend msgtypes(DEFAULT) "$event"
    }

    ## Initialize our encrypted incoming handler
    ## Binds to input from irc
    bind rawt - PRIVMSG ${ns}::incomingRawtPRIVMSG
    if {[IsTrue $keyx]} {
      bind nick - * ${ns}::keyx_nick
      bind notc - "DH1080_INIT *" ${ns}::keyx_bind
      bind notc - "DH1080_FINISH *" ${ns}::keyx_bind
    }
    if {[info exists topictrigger] && [IsFalse [string equal $topictrigger ""]]} {
      bind pub - $topictrigger ${ns}::IrcTopic
    }

    ## Binds to input from the ftp
    lappend precommand(SETTOPIC) ${ns}::LogEvent

    putlog "\[ngBot\] Blow :: Loaded successfully (Version: $blowversion)."
  }

  ####
  # Blow::DeInit
  #
  # Called on rehash; unregisters the event handler.
  #
  proc deinit {args} {
    variable ns
    variable np
    variable events
    variable keyxtimer
    variable topictrigger
    variable keyx
    variable putName
    variable ${np}::cmdpre
    variable ${np}::msgtypes

    ## Remove event callbacks.
    ## Remove event callbacks.
    if {[info commands "putquick2"] != ""} {
      interp alias {} putquick {}
      catch {rename ::putquick2 ::putquick}
    }
    if {[info commands "putserv2"] != ""} {
      interp alias {} putserv {}
      catch {rename ::putserv2  ::putserv}
    }
    if {[info commands "puthelp2"] != ""} {
      interp alias {} puthelp {}
      catch {rename ::puthelp2  ::puthelp}
    }
    if {[info commands "putnow2"] != ""} {
      catch {interp alias {} putnow {}}
      catch {rename ::putnow2  ::putnow}
    }

    foreach timer [array names keyxtimer] {
      catch {killutimer $keyxtimer($timer)}
    }

    ## Remove the SETTOPIC and GETTOPIC values from msgtypes(DEFAULT)
    foreach event $events {
      if {
        [info exists msgtypes(DEFAULT)]                                     && \
          [IsFalse [string equal [set pos [lsearch -exact $msgtypes(DEFAULT) $event]] "-1"]]} {
            set msgtypes(DEFAULT)   [lreplace $msgtypes(DEFAULT) $pos $pos]
        }
      }

      # Remove binds
      catch {unbind pub - +OK ${ns}::encryptedIncomingHandler}
      catch {unbind msg - +OK ${ns}::encryptedIncomingHandler}
      catch {bind rawt - PRIVMSG ${ns}::incomingRawtPRIVMSG}
      if {[IsTrue $keyx]} {
        catch {unbind nick - * ${ns}::keyx_nick}
        catch {unbind notc - "DH1080_INIT *" ${ns}::keyx_bind}
        catch {unbind notc - "DH1080_FINISH *" ${ns}::keyx_bind}
      }
      if {[info exists topictrigger] && [IsFalse [string equal $topictrigger ""]]} {
        catch {unbind pub - $topictrigger ${ns}::IrcTopic}
      }
      namespace delete $ns
      return
    }
  }
