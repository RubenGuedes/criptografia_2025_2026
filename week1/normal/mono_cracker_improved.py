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

# --------------------------- Quadgram Scoring ---------------------------
class QuadgramScorer:
    def __init__(self, quadgram_file='english_quadgrams.txt'):
        self.quadgrams = {}
        self.total = 0
        self.floor = None
        
        # load quadgram frequencies
        with open(quadgram_file, 'r') as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) == 2:
                    quad, count = parts[0], int(parts[1])
                    self.quadgrams[quad] = count
                    self.total += count

        # convert to log probabilities
        for quad in self.quadgrams:
            self.quadgrams[quad] = math.log10(self.quadgrams[quad] / self.total)
        
        # floor value for unseen quadgrams
        self.floor = math.log10(0.01 / self.total)
    
    def score(self, text):
        """Calculate fitness score for text using quadgram statistics."""
        score = 0
        for i in range(len(text) - 3):
            quad = text[i:i+4]
            score += self.quadgrams.get(quad, self.floor)
        return score

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
def solve(ctext, restarts=50, iters_per_restart=5000, seed=None, use_quadgrams=True):
    if seed is not None:
        random.seed(seed)

    # initialize quadgram scorer if available
    qscorer = None
    if use_quadgrams:
        try:
            qscorer = QuadgramScorer('english_quadgrams.txt')
            print("Quadgram scoring enabled")
        except FileNotFoundError:
            print("Warning: english_quadgrams.txt not found, using unigram scoring only")
            use_quadgrams = False

    best_score = float('-inf')
    best_mapping = None
    best_plain = None

    for r in range(restarts):
        print(f"Restart {r + 1}/{restarts}")
        
        # initial mapping and score using stats-based frequency mapping
        mapping = initial_key_by_frequency_using_stats(ctext)
        plain = apply_key_mapping(mapping, ctext)
        
        if use_quadgrams:
            score = qscorer.score(plain)
        else:
            score = -D(plain, ESTATS)  

        # simulated annealing schedule
        if use_quadgrams:
            T0 = 10.0
        else:
            T0 = max(0.5, abs(score) * 10)

        T = T0
        decay = 0.9995

        for it in range(iters_per_restart):
            # random swap of two letters in the key
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

            # apply swap
            mapping[ca], mapping[cb] = mapping[cb], mapping[ca]
            new_plain = apply_key_mapping(mapping, ctext)
            
            if use_quadgrams:
                new_score = qscorer.score(new_plain)
                delta = new_score - score
                accept = delta > 0 or random.random() < math.exp(delta / max(T, 1e-12))
            else:
                new_score = -D(new_plain, ESTATS)
                delta = new_score - score
                accept = delta > 0 or random.random() < math.exp(delta / max(T, 1e-12))

            if accept:
                plain = new_plain
                score = new_score
                if score > best_score:
                    best_score = score
                    best_mapping = mapping.copy()
                    best_plain = plain
                    print(f"  New best score: {score:.4f}")
            else:
                # revert swap
                mapping[ca], mapping[cb] = mapping[cb], mapping[ca]

            T *= decay

        # small random shake at end of each restart
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
    mapping, plain, score = solve(C, restarts=20, iters_per_restart=10000, seed=42, use_quadgrams=True)

    if mapping is None:
        print('No solution found')
    else:
        print('SOLUTION FOUND')
        print(f'Best score: {score:.2f}')
        print('\nMapping (ciphertext -> plaintext):')
        for i, ch in enumerate(ALPHABET):
            print(f"{ch} -> {mapping.get(ch, '?')}", end='\n')
        print('\n\nDecryption key:')
        encryption_key = ''.join([mapping.get(ch, '?') for ch in ALPHABET])
        print(f"ALPHABET: {ALPHABET}")
        print(f"KEY:      {encryption_key}")
        print('\n\nPlaintext:')
        print(plain)
