# compiled_pyke_files.py

from pyke import target_pkg

pyke_version = '1.1.1'
compiler_version = 1
target_pkg_version = 1

try:
    loader = __loader__
except NameError:
    loader = None

def get_target_pkg():
    return target_pkg.target_pkg(__name__, __file__, pyke_version, loader, {
         ('', '', 'rules.krb'):
           [1687998283.9034595, 'rules_bc.py'],
         ('', '', 'questions.kqb'):
           [1687998283.9139085, 'questions.qbc'],
        },
        compiler_version)

