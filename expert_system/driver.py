import sys

from pyke import knowledge_engine
from pyke import krb_traceback

engine = knowledge_engine.engine(__file__)


def main():
    engine.reset()
    try:
        engine.activate('rules')
        with engine.prove_goal('rules.calculate_score($score)') as gen:
            for vars, plan in gen:
                print('______________________________________________________________________________')
                print("Security score: %s" % (vars['score']))
    except Exception:
        krb_traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
