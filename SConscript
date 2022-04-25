Import( 'env' )
Import( 'compmap' )
import profiles
import shutil
import os
import time
import fnmatch
import SCons.Script
import sys

def run(cmd):
    """Run a command and decipher the return code. Exit by default."""
    res = os.system(cmd)
    # Assumes that if a process doesn't call exit, it was successful
    if (os.WIFEXITED(res)):
        code = os.WEXITSTATUS(res)
        if code != 0:
            print("Error: return code: " + str(code))
            sys.exit(code)

def BuildLibYara( target, source, env ):
    originalDir = os.getcwd()

    shutil.rmtree( os.path.join( Dir("#.").abspath, env[ 'BUILD_DIR' ], 'lib', 'yara' ) )

    shutil.copytree( os.path.join( Dir("#.").abspath, 'lib', 'yara' ),
                     os.path.join( Dir("#.").abspath, env[ 'BUILD_DIR' ], 'lib', 'yara' ) )

    os.chdir( os.path.join( Dir("#.").abspath, env[ 'BUILD_DIR' ], 'lib', 'yara' ) )

    target_host = env.get( 'crossCompileTo', None )
    if target_host is None:
        target_host = ''
    else:
        target_host = ' --host ' + target_host

    if 'arm' in env[ 'PLATFORM' ][ 'arch' ] and 'macos' in env[ 'PLATFORM' ][ 'name' ]:
        aboutCrypto = '--without-crypto'
    else:
        aboutCrypto = '--with-crypto'
        if 'macos' not in env[ 'PLATFORM' ][ 'name' ]:
            target_host += ' CFLAGS="-fPIC -I%s/include %s" LDFLAGS="-L%s/lib %s" --openssldir="%s"' % ( env[ 'openssl_dir' ],' '.join( env[ 'CFLAGS' ] ), env[ 'openssl_dir' ], ' '.join( env[ 'LDFLAGS' ] ), env[ 'openssl_dir' ] )

    run( './bootstrap.sh' )
    run( './configure --enable-static --disable-shared %s --disable-cuckoo%s' % ( aboutCrypto, target_host, ) )
    run( 'make' )

    shutil.copyfile( os.path.join( Dir("#.").abspath, env[ 'BUILD_DIR' ], 'lib', 'yara', 'libyara', '.libs', 'libyara.a' ),
                     os.path.join( Dir("#.").abspath, env[ 'BUILD_DIR' ], 'libyara.a' ) )

    os.chdir( originalDir )

def log_output_fn(target, source, env):
    """The message seen in build logs when this action is called"""
    #return "Building '%s'\n from '%s'\n at: %s" % (target[0], source[0],
    #  time.asctime(time.localtime(time.time())))
    return "Building: %s %s" % ( str( [ str( _ ) for _ in target ] ), str( [ str( _ ) for _ in source ] ) )

def recursiveGlob( dir ):
    matches = []
    for root, dirnames, filenames in os.walk(dir):
        for filename in fnmatch.filter(filenames, '*'):
            matches.extend(Glob(os.path.join(root, filename)))
    return matches

libyara = env.Command(
        target = os.path.join( '#', env[ 'BUILD_DIR' ], 'libyara.a' ),
        source = [],
        action = Action( BuildLibYara, strfunction = log_output_fn )
        )

class LibYara( profiles.Component ):
    def __init__( self, node ):
        super( LibYara, self ).__init__(
                "libyara",
                None,
                LIBS = [ "libyara" ],
                )
        self.node = node

compmap[ "libyara" ] = LibYara( libyara )

# EOF

