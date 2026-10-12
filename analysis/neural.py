"""Gohr-style neural distinguisher (the "AI attacker").

A multilayer perceptron sees output pairs (F(x), F(x^delta)) vs
(F(x), F(y)) and must tell them apart. Test accuracy significantly above
50% means a learned model has found structure in the round-reduced hash.
"""

import math

import numpy as np

from ramhash import lab


def _init(rng, fan_in, fan_out):
    return (rng.standard_normal((fan_in, fan_out)) *
            math.sqrt(2.0 / fan_in)).astype(np.float32)


def train_mlp(Xtr, ytr, Xte, yte, hidden=(512, 256), epochs=4, batch=1024,
              lr=1e-3, seed=0):
    """Adam-trained ReLU MLP with sigmoid output. Inputs are uint8 0/1 and
    are mapped to +-1 per batch to keep memory small. Returns test accuracy."""
    rng = np.random.default_rng(seed)
    sizes = (Xtr.shape[1],) + hidden + (1,)
    W = [_init(rng, a, b) for a, b in zip(sizes, sizes[1:])]
    B = [np.zeros(b, np.float32) for b in sizes[1:]]
    params = W + B
    m = [np.zeros_like(p) for p in params]
    v = [np.zeros_like(p) for p in params]
    t = 0

    def forward(x):
        acts = [x]
        for i in range(len(W) - 1):
            acts.append(np.maximum(acts[-1] @ W[i] + B[i], 0))
        logits = (acts[-1] @ W[-1] + B[-1])[:, 0]
        return acts, logits

    n = len(Xtr)
    for _ in range(epochs):
        order = rng.permutation(n)
        for s in range(0, n, batch):
            idx = order[s:s + batch]
            x = Xtr[idx].astype(np.float32) * 2 - 1
            y = ytr[idx].astype(np.float32)
            acts, logits = forward(x)
            p = 1 / (1 + np.exp(-np.clip(logits, -30, 30)))
            g = ((p - y) / len(idx))[:, None]
            gW, gB = [None] * len(W), [None] * len(W)
            for i in reversed(range(len(W))):
                gW[i] = acts[i].T @ g
                gB[i] = g.sum(0)
                if i:
                    g = (g @ W[i].T) * (acts[i] > 0)
            t += 1
            for j, (p_, g_) in enumerate(zip(params, gW + gB)):
                m[j] = 0.9 * m[j] + 0.1 * g_
                v[j] = 0.999 * v[j] + 0.001 * g_ * g_
                mh = m[j] / (1 - 0.9 ** t)
                vh = v[j] / (1 - 0.999 ** t)
                p_ -= lr * mh / (np.sqrt(vh) + 1e-8)
    correct = 0
    for s in range(0, len(Xte), 8192):
        _, logits = forward(Xte[s:s + 8192].astype(np.float32) * 2 - 1)
        correct += int(((logits > 0) == (yte[s:s + 8192] == 1)).sum())
    return correct / len(Xte)


def distinguish(alg, rounds, delta_bit, n_train=400_000, n_test=100_000,
                epochs=4, seed=1):
    """Returns (accuracy, z-score vs. 50%)."""
    Xtr, ytr = lab.pairs(alg, rounds, delta_bit, n_train, seed=seed)
    Xte, yte = lab.pairs(alg, rounds, delta_bit, n_test, seed=seed + 7919)
    acc = train_mlp(Xtr, ytr, Xte, yte, epochs=epochs)
    z = (acc - 0.5) / math.sqrt(0.25 / n_test)
    return acc, z
