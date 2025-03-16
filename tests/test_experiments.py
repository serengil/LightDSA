# built-in dependencies
import time

# 3rd party dependencies
from tqdm import tqdm
from lightdsa import LightDSA
from lightecc.curves.inventory import list_curves


def __test_experiments():
    m = "Hello, World!"

    configs = []
    for algorithm in ["eddsa", "ecdsa"]:
        for form in ["weierstrass", "koblitz", "edwards"]:
            curves = list_curves(form_name=form)
            for curve in curves:
                if curve == "test-curve":
                    continue
                configs.append((algorithm, form, curve))

    results = []
    for algorithm, form, curve in tqdm(configs):
        tic = time.time()
        dsa = LightDSA(algorithm_name=algorithm, form_name=form, curve_name=curve)

        n = dsa.dsa.curve.n
        hash_algorithm = dsa.dsa.hash_algorithm

        toc = time.time()
        key_gen = toc - tic

        tic = time.time()
        signature = dsa.sign(m)
        toc = time.time()
        sign_time = toc - tic

        tic = time.time()
        dsa.verify(m, signature)
        toc = time.time()
        verify_time = toc - tic

        results.append(
            (algorithm, form, curve, n, hash_algorithm, key_gen, sign_time, verify_time)
        )

    for (
        algorithm,
        form,
        curve,
        n,
        hash_algorithm,
        key_gen,
        sign_time,
        verify_time,
    ) in results:
        print(
            f"{algorithm} | {form} | {curve} | {n} | {hash_algorithm} | {key_gen:.4f} | {sign_time:.4f} | {verify_time:.4f}"
        )
