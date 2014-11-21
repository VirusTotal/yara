#!/bin/bash 


_version='1.02'
	
_plan_set=0
_no_plan=0
_skip_all=0
_test_died=0
_expected_tests=0 
_executed_tests=0 
_failed_tests=0
TODO=


usage(){
	cat <<'USAGE'
tap-functions: A TAP-producing BASH library

PLAN:
  plan_no_plan
  plan_skip_all [REASON]
  plan_tests NB_TESTS

TEST:
  ok RESULT [NAME]
  okx COMMAND
  is RESULT EXPECTED [NAME]
  isnt RESULT EXPECTED [NAME]
  like RESULT PATTERN [NAME]
  unlike RESULT PATTERN [NAME]
  pass [NAME]
  fail [NAME]

SKIP:
  skip [CONDITION] [REASON] [NB_TESTS=1]

  skip $feature_not_present "feature not present" 2 || {
      is $a "a"
      is $b "b"
  }

TODO:
  Specify TODO mode by setting $TODO:
    TODO="not implemented yet"
    ok $result "some not implemented test"
    unset TODO

OTHER:
  diag MSG

EXAMPLE:
  #!/bin/bash

  . tap-functions

  plan_tests 7

  me=$USER
  is $USER $me "I am myself"
  like $HOME $me "My home is mine"
  like "`id`" $me "My id matches myself"

  /bin/ls $HOME 1>&2
  ok $? "/bin/ls $HOME"
  # Same thing using okx shortcut
  okx /bin/ls $HOME

  [[ "`id -u`" != "0" ]]
  i_am_not_root=$?
  skip $i_am_not_root "Must be root" || {
    okx ls /root
  }

  TODO="figure out how to become root..."
  okx [ "$HOME" == "/root" ]
  unset TODO
USAGE
	exit
}

opt=
set_u=
while getopts ":sx" opt ; do
	case $_opt in
        u) set_u=1 ;;
        *) usage ;;
    esac
done
shift $(( OPTIND - 1 ))
# Don't allow uninitialized variables if requested
[[ -n "$set_u" ]] && set -u
unset opt set_u

# Used to call _cleanup on shell exit
trap _exit EXIT



plan_no_plan(){
	(( _plan_set != 0 )) && "You tried to plan twice!"

	_plan_set=1
	_no_plan=1

	return 0
}


plan_skip_all(){
	local reason=${1:-''}

	(( _plan_set != 0 )) && _die "You tried to plan twice!"

	_print_plan 0 "Skip $reason"

	_skip_all=1
	_plan_set=1
	_exit 0

	return 0
}


plan_tests(){
	local tests=${1:?}

	(( _plan_set != 0 )) && _die "You tried to plan twice!"
	(( tests == 0 )) && _die "You said to run 0 tests!  You've got to run something."

	_print_plan $tests
	_expected_tests=$tests
	_plan_set=1

	return $tests
}


_print_plan(){
	local tests=${1:?}
	local directive=${2:-''}

	echo -n "1..$tests"
	[[ -n "$directive" ]] && echo -n " # $directive"
	echo
}


pass(){
	local name=$1
	ok 0 "$name"
}


fail(){
	local name=$1
	ok 1 "$name"
}


# This is the workhorse method that actually
# prints the tests result.
ok(){
	local result=${1:?}
	local name=${2:-''}

	(( _plan_set == 0 )) && _die "You tried to run a test without a plan!  Gotta have a plan."

	_executed_tests=$(( $_executed_tests + 1 ))

	if [[ -n "$name" ]] ; then
		if _matches "$name" "^[0-9]+$" ; then
			diag "    You named your test '$name'.  You shouldn't use numbers for your test names."
			diag "    Very confusing."
		fi
	fi

	if (( result != 0 )) ; then
		echo -n "not "
		_failed_tests=$(( _failed_tests + 1 ))
	fi
	echo -n "ok $_executed_tests"

	if [[ -n "$name" ]] ; then
		local ename=${name//\#/\\#}
		echo -n " - $ename"
	fi

	if [[ -n "$TODO" ]] ; then
		echo -n " # TODO $TODO" ;
		if (( result != 0 )) ; then
			_failed_tests=$(( _failed_tests - 1 ))
		fi
	fi

	echo
	if (( result != 0 )) ; then
		local file='tap-functions'
		local func=
		local line=

		local i=0
		local bt=$(caller $i)
		while _matches "$bt" "tap-functions$" ; do
			i=$(( $i + 1 ))
			bt=$(caller $i)
		done
		local backtrace=
		eval $(caller $i | (read line func file ; echo "backtrace=\"$file:$func() at line $line.\""))
			
		local t=
		[[ -n "$TODO" ]] && t="(TODO) "

		if [[ -n "$name" ]] ; then
			diag "  Failed ${t}test '$name'"
			diag "  in $backtrace"
		else
			diag "  Failed ${t}test in $backtrace"
		fi
	fi

	return $result
}


okx(){
	local command="$@"

	local line=
	diag "Output of '$command':"
	$command | while read line ; do
		diag "$line"
	done
	ok ${PIPESTATUS[0]} "$command"
}


_equals(){
	local result=${1:?}
	local expected=${2:?}

	if [[ "$result" == "$expected" ]] ; then
		return 0
	else 
		return 1
	fi
}


# Thanks to Aaron Kangas for the patch to allow regexp matching
# under bash < 3.
 _bash_major_version=${BASH_VERSION%%.*}
_matches(){
	local result=${1:?}
	local pattern=${2:?}

	if [[ -z "$result" || -z "$pattern" ]] ; then
		return 1
	else
		if (( _bash_major_version >= 3 )) ; then
			eval '[[ "$result" =~ "$pattern" ]]'
		else
			echo "$result" | egrep -q "$pattern"
		fi
	fi
}


_is_diag(){
	local result=${1:?}
	local expected=${2:?}

	diag "         got: '$result'" 
	diag "    expected: '$expected'"
}


is(){
	local result=${1:?}
	local expected=${2:?}
	local name=${3:-''}

	_equals "$result" "$expected"
	(( $? == 0 ))
	ok $? "$name"
	local r=$?
	(( r != 0 )) && _is_diag "$result" "$expected"
	return $r 
}


isnt(){
	local result=${1:?}
	local expected=${2:?}
	local name=${3:-''}

	_equals "$result" "$expected"
	(( $? != 0 ))
	ok $? "$name"
	local r=$?
	(( r != 0 )) && _is_diag "$result" "$expected"
	return $r 
}


like(){
	local result=${1:?}
	local pattern=${2:?}
	local name=${3:-''}

	_matches "$result" "$pattern"
	(( $? == 0 ))
	ok $? "$name"
	local r=$?
	(( r != 0 )) && diag "    '$result' doesn't match '$pattern'"
	return $r
}


unlike(){
	local result=${1:?}
	local pattern=${2:?}
	local name=${3:-''}

	_matches "$result" "$pattern"
	(( $? != 0 ))
	ok $? "$name"
	local r=$?
	(( r != 0 )) && diag "    '$result' matches '$pattern'"
	return $r
}


skip(){
	local condition=${1:?}
	local reason=${2:-''}
	local n=${3:-1}

	if (( condition == 0 )) ; then
		local i=
		for (( i=0 ; i<$n ; i++ )) ; do
			_executed_tests=$(( _executed_tests + 1 ))
			echo "ok $_executed_tests # skip: $reason" 
		done
		return 0
	else
		return
	fi
}


diag(){
	local msg=${1:?}

	if [[ -n "$msg" ]] ; then
		echo "# $msg"
	fi
	
	return 1
}

	
_die(){
	local reason=${1:-'<unspecified error>'}

	echo "$reason" >&2
	_test_died=1
	_exit 255
}


BAIL_OUT(){
	local reason=${1:-''}

	echo "Bail out! $reason" >&2
	_exit 255
}


_cleanup(){
	local rc=0

	if (( _plan_set == 0 )) ; then
		diag "Looks like your test died before it could output anything."
		return $rc
	fi

	if (( _test_died != 0 )) ; then
		diag "Looks like your test died just after $_executed_tests."
		return $rc
	fi

	if (( _skip_all == 0 && _no_plan != 0 )) ; then
		_print_plan $_executed_tests
	fi

	local s=
	if (( _no_plan == 0 && _expected_tests < _executed_tests )) ; then
		s= ; (( _expected_tests > 1 )) && s=s
		local extra=$(( _executed_tests - _expected_tests ))
		diag "Looks like you planned $_expected_tests test$s but ran $extra extra."
		rc=-1 ;
	fi

	if (( _no_plan == 0 && _expected_tests > _executed_tests )) ; then
		s= ; (( _expected_tests > 1 )) && s=s
		diag "Looks like you planned $_expected_tests test$s but only ran $_executed_tests."
	fi

	if (( _failed_tests > 0 )) ; then
		s= ; (( _failed_tests > 1 )) && s=s
		diag "Looks like you failed $_failed_tests test$s of $_executed_tests."
	fi

	return $rc
}


_exit_status(){
	if (( _no_plan != 0 || _plan_set == 0 )) ; then
		return $_failed_tests
	fi

	if (( _expected_tests < _executed_tests )) ; then
		return $(( _executed_tests - _expected_tests  ))
	fi

	return $(( _failed_tests + ( _expected_tests - _executed_tests )))
}


_exit(){
	local rc=${1:-''}
	if [[ -z "$rc" ]] ; then
		_exit_status
		rc=$?
	fi

	_cleanup
	local alt_rc=$?
	(( alt_rc != 0 )) && rc=$alt_rc
	trap - EXIT
	exit $rc
}

