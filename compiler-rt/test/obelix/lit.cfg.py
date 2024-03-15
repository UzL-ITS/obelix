# -*- Python -*-

import os

# Setup config name.
config.name = 'Obelix'

# Setup source root.
config.test_source_root = os.path.dirname(__file__)

# Test suffixes.
config.suffixes = ['.c', '.cpp', '.m', '.mm', '.ll', '.test']

# Add clang substitutions.
config.substitutions.append( ("%clang_noobelix ", config.clang + ' -O0 -fno-sanitize=obelix ' + config.target_cflags + ' ') )

obelix_arch_cflags = config.target_cflags
config.substitutions.append( ("%clang_obelix ", config.clang + ' -O0 -fsanitize=obelix ' + obelix_arch_cflags + ' ') )

if config.host_os not in ['Linux'] or config.target_arch not in ['x86_64']:
    config.unsupported = True
