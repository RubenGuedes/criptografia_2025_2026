import string
import random
import math
from collections import Counter

# --------------------------- Provided helpers ---------------------------
ALPHABET = string.ascii_uppercase

# --------------------------- Scoring and stats ---------------------------
ESTATS = [
 0.0827031042166906, 0.0162276080084299, 0.0304341066523865, 0.0375304461987597,
 0.122672701204028, 0.0212717442001071, 0.0213201126293424, 0.0502686175266458,
 0.0748777833439859, 0.00192437250600287, 0.00767676069719636, 0.0423189206930505,
 0.0274732678056280, 0.0709564856881273, 0.0748432344659607, 0.0196341273817133,
 0.00130594758935204, 0.0634870182590820, 0.0662509285010969, 0.0866554958627719,
 0.0301577156281850, 0.0101919190174299, 0.0179861458999119, 0.00233550415450258,
 0.0183247249045587, 0.00117120696505381
]

def stats(text):
    """Return list of 26 frequencies (probabilities) for A..Z of uppercase text."""
    assert all(c in ALPHABET for c in text), "text must be uppercase A-Z only"
    st = [0] * 26
    for c in text:
        st[ord(c) - 65] += 1
    l = sum(st)
    if l == 0:
        return [0.0] * 26
    return [x / float(l) for x in st]

def D(text, ref):
    p = stats(text)
    return sum((ref[i] - p[i]) ** 2 for i in range(26))

# --------------------------- Utilities ---------------------------
def apply_key_mapping(mapping, text):
    # mapping: dict ciphertext_letter -> plaintext_letter
    return ''.join(mapping.get(c, '?') for c in text)


def mapping_to_key_string(mapping):
    # produce 26-char key string where position i is mapping of ciphertext letter chr(65+i)
    return ''.join(mapping.get(chr(65 + i), '?') for i in range(26))


# build initial mapping by mapping ciphertext letter frequencies (from stats) to ESTATS
def initial_key_by_frequency_using_stats(ctext):
    p = stats(ctext)
    freq_sorted = sorted(ALPHABET, key=lambda c: -p[ord(c) - 65])
    eng_sorted = sorted(ALPHABET, key=lambda c: -ESTATS[ord(c) - 65])
    mapping = { }
    for i, ch in enumerate(freq_sorted):
        mapping[ch] = eng_sorted[i]
    return mapping


# convenience: convert mapping (ct->pt) to inverse (pt->ct)
def invert_mapping(mapping):
    inv = {v: k for k, v in mapping.items()}
    return inv

# --------------------------- Solver ---------------------------

def solve(ctext, restarts=50, iters_per_restart=5000, seed=None):
    if seed is not None:
        random.seed(seed)

    best_score = float('inf')
    best_mapping = None
    best_plain = None

    for r in range(restarts):
        print(f"Restart {r + 1}/{restarts}")
        
        # initial mapping and score using stats-based frequency mapping
        mapping = initial_key_by_frequency_using_stats(ctext)
        plain = apply_key_mapping(mapping, ctext)
        score = D(plain, ESTATS)

        # simulated annealing schedule
        T0 = max(0.5, score * 10)
        T = T0
        decay = 0.9995

        for it in range(iters_per_restart):
            a, b = random.sample(ALPHABET, 2)
            ca = cb = None
            for k, v in mapping.items():
                if v == a:
                    ca = k
                elif v == b:
                    cb = k
                if ca and cb:
                    break
            if ca is None or cb is None:
                continue

            mapping[ca], mapping[cb] = mapping[cb], mapping[ca]
            new_plain = apply_key_mapping(mapping, ctext)
            new_score = D(new_plain, ESTATS)
            delta = new_score - score

            if delta < 0 or random.random() < math.exp(-delta / max(T, 1e-12)):
                plain = new_plain
                score = new_score
                if score < best_score:
                    best_score = score
                    best_mapping = mapping.copy()
                    best_plain = plain
            else:
                mapping[ca], mapping[cb] = mapping[cb], mapping[ca]

            T *= decay

        # small random shake
        for _ in range(10):
            x, y = random.sample(ALPHABET, 2)
            ca = cb = None
            for k, v in mapping.items():
                if v == x:
                    ca = k
                elif v == y:
                    cb = k
                if ca and cb:
                    break
            if ca and cb:
                mapping[ca], mapping[cb] = mapping[cb], mapping[ca]

    return best_mapping, best_plain, best_score


# --------------------------- Example run ---------------------------
if __name__ == '__main__':
    CIPHERTEXT = (
        "KNAPNUKSQNAWSXEFRPAWAUQAFNAWUQFSPREQZNUGAFRQUTEUPAKFNAFZMUWWTFNUFFNZQKAOQFXHHZKFNAIRF"
        "FWAUHHAMFQFNAHAAWRHFNZKJQZKUIZJOUTAGAKKROVTHAAWZKJRLZQUQQRMZUFASOZFNAGAKFQUKSEAREWAJRFFUWRG"
        "AFNAVRPOUKFFNAVRPNUFARPHAUPFNAVFNAQAUQQRMZUFZRKQOZWWIAMRVAEPRJPAQQZGAWTVRPAAWUIRPUFAUQZUMMXV"
        "XWUFAVRPAABEAPZAKMAQRRKZMUKQUTZHAAWZUVMRWSUKSMRKFAVEFXRXQRHRFNAPQIAMUXQAZUVUHPUZSFRABEAPZAKM"
        "AFNAZPPADAMFZRKRHVARPZWRGANZVIAMUXQANAVULAQVAHAAWQAMXPAUKSMRKHZSAKFUKSOUKFASFNAABEWUKUFZRKQOZW"
        "WKRFEUPFZMXWUPWTNAWEZKHAAWZKJIAFFAPZHRKAHAAWQIUSMRKGAPQAWTFPTZKJFRHAAWJRRSOZWWKRFQAAVFRIAAKNUK"
        "MASITJRRSABEWUKUFZRKQZOZWWWZGAFNPRXJNTAUPQRHFNAPUEZQFQAKMRXPUJZKJVAFRABEAPZAKMAVTEQTMNZMORXKSVT"
        "HAAWZKJQOZFNFNAZSAUFNUFZMUKUMNZAGAUQFUFARHIAZKJZKONZMNEUZKMUKIAABEAPZAKMASOZFNRXFSAIZWZFUFZKJMR"
        "KQACXAKMAQZOZWWUQLKROONZWAZNUGAABFPUQTKUEQAQZQKFZFFNAKUPPUFZGAZFQAWHFNUFZKQMPZIAQFNAQMUPQRKRXPV"
        "ZKSQRXPNAUPFQVTHXFXPAPUYRPMXFUSRWAQMAKFUPVQZORKSAPZHZFDXQFORXWSKFIAIAFFAPFRQLZEFNAEUZKUWFRJAFNAP"
        "QNAQWZEQHUWWQRKNAPIUMLXKMRKQMZRXQXPZKAQEPAUSQZKUERRWFROUPSFNAHPUTASAWA"
    )

    # format ciphertext: uppercase letters only
    C = ''.join([c for c in CIPHERTEXT if c in ALPHABET])

    print('Running solver...')
    mapping, plain, score = solve(C, restarts=50, iters_per_restart=10000, seed=42)

    if mapping is None:
        print('No solution found')
    else:
        print('Best D score: {:.8f}'.format(score))
        print('Mapping (ciphertext -> plaintext):')
        for i, ch in enumerate(ALPHABET):
            print(f"{ch} -> {mapping.get(ch, '?')}", end='; \n')
        print('Best plaintext candidate:')
        print(plain)