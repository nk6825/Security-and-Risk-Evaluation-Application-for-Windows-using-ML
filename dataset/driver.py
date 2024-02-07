import random
import sys
import pandas as pd

from pyke import knowledge_engine
from pyke import krb_traceback

engine = knowledge_engine.engine(__file__)


def sum(a, b, c, d, e, f):
    return a + b + c + d + e + f


def main():
    dataset = []
    for _ in range(40000):
        rps = random.randint(0, 4)
        ac = random.choice([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
        wps = bool(random.getrandbits(1))
        fs = bool(random.getrandbits(1))
        mc = random.choice([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
        uacs = bool(random.getrandbits(1))
        engine.reset()
        try:
            engine.activate('rules')
            with engine.prove_goal(
                    'rules.calculate_score($score, $l1, $l2, $l3, $l4, $l5, $l6, $v1, $v2, $v3, $v4, $v5, $v6)', v1=rps,
                    v2=ac, v3=wps, v4=fs, v5=mc, v6=uacs) as gen:
                for vars, plan in gen:
                    print('______________________________________________________________________________')
                    print("Security score: %s" % (vars['score']))
        except Exception:
            krb_traceback.print_exc()
            sys.exit(1)
        dataset.append([rps, ac, wps, fs, mc, uacs, vars['score']])

    df = pd.DataFrame(dataset)
    df.drop_duplicates()
    file_path = 'dataset.csv'
    df.to_csv(file_path, index=False, header=False)
    df = pd.read_csv(file_path)
    df = df.drop_duplicates()
    df.to_csv(file_path, index=False)


if __name__ == '__main__':
    main()
