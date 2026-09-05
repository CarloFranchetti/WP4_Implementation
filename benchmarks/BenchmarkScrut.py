"""
Benchmark della fase di scrutinio e conteggio dei voti.
Misura:
  - Costo computazionale delle singole operazioni crittografiche dello scrutinio
  - Dimensione dei messaggi scambiati (schede cifrate, payload firmato)
  - Latenza delle operazioni di verifica (firma AE, decifrazione, firma AS)
  - Tempi end-to-end dello scrutinio completo
  - Scalabilità al variare del numero di elettori
"""
import os
import time
import statistics

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from archive.PublicDirectory import PublicDirectory
from entities.Voter import Voter
from entities.Ballot import Ballot
from entities.ElectoralAuthority import ElectoralAuthority
from entities.ScrutinyAuthority import ScrutinyAuthority
from pki.StateCA import StateCA
from pki.MunicipalityCA import MunicipalityCA
from utils.crypto_utils import (
    rsa_encrypt, rsa_decrypt, sign_pss, verify_pss, sha256, hybrid_encrypt
)


def measure(fn, label, iterations=10):
    """Executes fn() 'iterations' times and returns statistics in ms."""
    times = []
    result = None
    for _ in range(iterations):
        start = time.perf_counter()
        result = fn()
        elapsed = (time.perf_counter() - start) * 1000  # ms
        times.append(elapsed)
    return {
        "label": label,
        "mean_ms": statistics.mean(times),
        "median_ms": statistics.median(times),
        "stdev_ms": statistics.stdev(times) if len(times) > 1 else 0,
        "min_ms": min(times),
        "max_ms": max(times),
        "iterations": iterations,
        "result": result
    }


def print_header(title):
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}")


def print_metric(m):
    print(f"  {m['label']:.<50s} {m['mean_ms']:8.2f} ms  "
          f"(med: {m['median_ms']:.2f}, σ: {m['stdev_ms']:.2f}, "
          f"min: {m['min_ms']:.2f}, max: {m['max_ms']:.2f})")


# =====================================================================
# SETUP — Creazione dell'ambiente di voto completo
# =====================================================================
print_header("SETUP — Creazione dell'ambiente di voto")

state_ca = StateCA("Italy")
municipality = MunicipalityCA("Vietri Sul Mare", state_ca)
ea = ElectoralAuthority("National Electoral Authority", state_ca)
sa = ScrutinyAuthority("National Scrutiny Authority", state_ca)

pd = PublicDirectory()
pd.set_root_ca(state_ca.certificate)
pd.add_municipality(municipality.certificate)
pd.add_authority(ea.certificate)
pd.add_authority(sa.certificate)

pk_ae = ea.get_public_key()
pk_as = sa.get_public_key()


def register_and_vote(name, choice):
    """Registra un elettore e lo fa votare, restituisce la ricevuta."""
    v = Voter(name)
    csr = v.generate_certificate_request()
    v.set_certificate(municipality.sign_voter_csr(csr))
    enc_req = v.request_ballot(pk_ae)
    blank, sig = ea.receive_ballot_request(enc_req, pd)
    v.receive_blank_ballot(blank, sig, pk_ae)
    payload = v.submit_ballot(choice, pk_ae, pk_as)
    receipt = ea.receive_encrypted_ballot(payload, v.get_public_key(), pk_as)
    return v, receipt


# Registra 4 elettori base per i benchmark
print("  Registrazione 4 elettori di base...")
v1, _ = register_and_vote("Peppe", "SI")
v2, _ = register_and_vote("Mario", "NO")
v3, _ = register_and_vote("Lucia", "ASTENUTO")
v4, _ = register_and_vote("Giovanni", "SI")
print(f"4 elettori registrati — Bulletin Board: {len(ea.bulletin_board)} schede")
print(f"Voti: SI=2, NO=1, ASTENUTO=1")


# =====================================================================
# 1. COSTO COMPUTAZIONALE — Operazioni Crittografiche dello Scrutinio
# =====================================================================
print_header("1. COSTO COMPUTAZIONALE — Operazioni dello Scrutinio")

# --- SHA-256 hash di una scheda cifrata ---
print("\n  [SHA-256 — Hash della scheda cifrata]")
sample_encrypted_ballot = ea.bulletin_board[0]["encrypted_ballot"]

m_sha256 = measure(
    lambda: sha256(sample_encrypted_ballot),
    "SHA-256(schedacifrata) — 512 byte", iterations=1000
)
print_metric(m_sha256)

# --- Verifica firma AE (RSA-PSS) ---
print("\n  [Verifica firma AE — RSA-PSS SHA-256]")
sample_ae_sig = ea.bulletin_board[0]["ae_signature"]
sample_hash = sha256(sample_encrypted_ballot)

m_verify_ae = measure(
    lambda: verify_pss(sample_ae_sig, sample_hash, pk_ae),
    "Vrfy(pkAE, σAE, Hash(scheda)) — RSA-PSS 4096", iterations=100
)
print_metric(m_verify_ae)

# --- Verifica firma AE con firma invalida (deve fallire) ---
fake_sig = os.urandom(512)
m_verify_ae_fail = measure(
    lambda: verify_pss(fake_sig, sample_hash, pk_ae),
    "Vrfy(pkAE, σ_falsa, Hash(scheda)) — deve fallire", iterations=100
)
print_metric(m_verify_ae_fail)

# --- Decifrazione RSA-OAEP (scheda cifrata -> ballot) ---
print("\n  [Decifrazione RSA-OAEP — skAS]")
m_decrypt = measure(
    lambda: rsa_decrypt(sample_encrypted_ballot, sa._private_key),
    "RSA-OAEP-Dec(skAS, schedacifrata) — 4096 bit", iterations=100
)
print_metric(m_decrypt)

# --- Deserializzazione Ballot + conversione voto ---
print("\n  [Deserializzazione Ballot + to_vote_value()]")
sample_plaintext = rsa_decrypt(sample_encrypted_ballot, sa._private_key)

m_deser = measure(
    lambda: Ballot.from_bytes(sample_plaintext).to_vote_value(),
    "Ballot.from_bytes() + to_vote_value()", iterations=1000
)
print_metric(m_deser)

# --- Firma RSA-PSS del payload risultato ---
print("\n  [Firma RSA-PSS — skAS sul payload risultato]")
# Simula un payload realistico
sample_payload = b'{"authority":"AS","result":{"count_si":2,"count_no":1,"count_null":1},"encrypted_ballots":[]}'

m_sign_as = measure(
    lambda: sign_pss(sample_payload, sa._private_key),
    "Sign(skAS, payload) — RSA-PSS 4096", iterations=50
)
print_metric(m_sign_as)

# --- Verifica firma AS sul risultato ---
print("\n  [Verifica firma AS — RSA-PSS SHA-256]")
sample_as_sig = sign_pss(sample_payload, sa._private_key)

m_verify_as = measure(
    lambda: verify_pss(sample_as_sig, sample_payload, pk_as),
    "Vrfy(pkAS, σAS, payload) — RSA-PSS 4096", iterations=100
)
print_metric(m_verify_as)


# =====================================================================
# 2. DIMENSIONE DEI MESSAGGI DELLA FASE DI SCRUTINIO
# =====================================================================
print_header("2. DIMENSIONE DEI MESSAGGI — Fase di Scrutinio")

# Esegui lo scrutinio per ottenere dati reali
tally_result = sa.tally_votes(ea.bulletin_board, pk_ae)

print(f"\n  {'Messaggio':.<50s} {'Bytes':>8s}")
print(f"  {'-' * 60}")

# Singola scheda cifrata (RSA-OAEP, dimensione fissa = key_size // 8)
ballot_size = len(sample_encrypted_ballot)
print(f"  {'Scheda cifrata (Enc(pkAS, ballot)) — RSA-OAEP':.<50s} {ballot_size:>8d} bytes")

# Firma AE su una scheda (RSA-PSS, dimensione fissa = key_size // 8)
sig_size = len(sample_ae_sig)
print(f"  {'Firma AE su scheda (σAE) — RSA-PSS 4096':.<50s} {sig_size:>8d} bytes")

# Hash SHA-256
hash_size = len(sample_hash)
print(f"  {'Hash SHA-256(schedacifrata)':.<50s} {hash_size:>8d} bytes")

# Entry singola della Bulletin Board
entry_size = ballot_size + sig_size
print(f"  {'Entry Bulletin Board (scheda + firma AE)':.<50s} {entry_size:>8d} bytes")

# Bulletin Board completa (4 schede)
board_size = entry_size * len(ea.bulletin_board)
board_label = f"Bulletin Board completa ({len(ea.bulletin_board)} schede)"
print(f"  {board_label:.<50s} {board_size:>8d} bytes")

print(f"  {'-' * 60}")

# Payload firmato da AS (risultato + schede cifrate)
payload_size = len(tally_result["signed_payload"])
print(f"  {'Payload firmato AS (risultato + schede cifrate)':.<50s} {payload_size:>8d} bytes")

# Firma AS sul payload
as_sig_size = len(tally_result["as_signature"])
print(f"  {'Firma AS sul payload (σAS) — RSA-PSS 4096':.<50s} {as_sig_size:>8d} bytes")

# Totale pubblicazione AS
total_pub = payload_size + as_sig_size
print(f"  {'TOTALE pubblicazione AS (payload + σAS)':.<50s} {total_pub:>8d} bytes")

print(f"\n  [Stima scalabilità dimensionale]")
for n in [10, 50, 100, 1000]:
    # Stima: payload cresce linearmente con il numero di schede
    # Ogni scheda cifrata in base64 ≈ ballot_size * 4/3 + overhead JSON
    estimated_payload = 200 + n * (ballot_size * 4 // 3 + 10)  # overhead JSON
    estimated_total = estimated_payload + 512  # firma AS
    print(f"  {n:>5d} schede → payload stimato: ~{estimated_total:>8d} bytes "
          f"(~{estimated_total / 1024:.1f} KB)")


# =====================================================================
# 3. LATENZA DELLE OPERAZIONI DI VERIFICA DELLO SCRUTINIO
# =====================================================================
print_header("3. LATENZA OPERAZIONI DI VERIFICA — Scrutinio")

print("\n  [Verifica singola scheda (hash + verify firma AE)]")


def verify_single_ballot():
    entry = ea.bulletin_board[0]
    h = sha256(entry["encrypted_ballot"])
    return verify_pss(entry["ae_signature"], h, pk_ae)


m_verify_single = measure(verify_single_ballot,
                          "Verifica singola scheda (SHA-256 + Vrfy PSS)", iterations=100)
print_metric(m_verify_single)

print("\n  [Decifrazione singola scheda (decrypt + deserialize + convert)]")


def decrypt_single_ballot():
    entry = ea.bulletin_board[0]
    plaintext = rsa_decrypt(entry["encrypted_ballot"], sa._private_key)
    ballot = Ballot.from_bytes(plaintext)
    return ballot.to_vote_value()


m_decrypt_single = measure(decrypt_single_ballot,
                           "Decifrazione singola (Dec + from_bytes + to_vote)", iterations=100)
print_metric(m_decrypt_single)

print("\n  [Verifica universale]")

m_verify_tally = measure(
    lambda: ScrutinyAuthority.verify_tally(
        tally_result["signed_payload"],
        tally_result["as_signature"],
        pk_as
    ),
    "Vrfy(pkAS, σAS, payload) — verifica universale", iterations=100
)
print_metric(m_verify_tally)

m_verify_consistency = measure(
    lambda: ScrutinyAuthority.verify_ballot_consistency(
        tally_result["signed_payload"],
        ea.bulletin_board
    ),
    "Confronto schede (payload AS <-> Bulletin Board AE)", iterations=100
)
print_metric(m_verify_consistency)

print("\n  [Verifica universale completa (firma + confronto schede)]")


def full_universal_verification():
    sig_ok = ScrutinyAuthority.verify_tally(
        tally_result["signed_payload"],
        tally_result["as_signature"],
        pk_as
    )
    consistency_ok = ScrutinyAuthority.verify_ballot_consistency(
        tally_result["signed_payload"],
        ea.bulletin_board
    )
    return sig_ok and consistency_ok


m_full_vu = measure(full_universal_verification,
                    "Verifica universale completa", iterations=100)
print_metric(m_full_vu)

print("\n  [Verifica individuale]")
sample_receipt = ea.bulletin_board[0]["ae_signature"]
m_verify_individual = measure(
    lambda: ScrutinyAuthority.verify_individual(sample_receipt, tally_result["signed_payload"]),
    "Ricerca ricevuta nel payload (Verifica individuale)", iterations=1000
)
print_metric(m_verify_individual)


# =====================================================================
# 4. TEMPI END-TO-END DELLO SCRUTINIO
# =====================================================================
print_header("4. TEMPI END-TO-END — Scrutinio Completo")

print("\n  [Scrutinio completo (4 schede): verifica + decifrazione + conteggio + firma]")

m_tally_4 = measure(
    lambda: sa.tally_votes(ea.bulletin_board, pk_ae),
    "tally_votes() — 4 schede", iterations=20
)
print_metric(m_tally_4)

# Breakdown: costo per-scheda stimato
per_ballot_ms = m_tally_4["mean_ms"] / len(ea.bulletin_board)
print(f"\n  Costo stimato per scheda (4 schede): {per_ballot_ms:.2f} ms")


# =====================================================================
# 5. SCALABILITÀ — Scrutinio con N elettori
# =====================================================================
print_header("5. SCALABILITÀ — Scrutinio con N elettori")

for n_voters in [10, 50, 100]:
    # Crea un ambiente fresco per ciascun test
    sca_s = StateCA("Italy")
    mun_s = MunicipalityCA("Vietri Sul Mare", sca_s)
    ea_s = ElectoralAuthority("Electoral Authority", sca_s)
    sa_s = ScrutinyAuthority("Scrutiny Authority", sca_s)

    pd_s = PublicDirectory()
    pd_s.set_root_ca(sca_s.certificate)
    pd_s.add_municipality(mun_s.certificate)
    pd_s.add_authority(ea_s.certificate)
    pd_s.add_authority(sa_s.certificate)

    ae_pk = ea_s.get_public_key()
    pk_as = sa_s.get_public_key()

    # Fase di votazione: registra N elettori
    choices = ["SI", "NO", "ASTENUTO"]
    print(f"\n  [{n_voters} elettori] Fase di votazione...", end="", flush=True)
    t_vote_start = time.perf_counter()
    for i in range(n_voters):
        choice = choices[i % 3]
        v = Voter(f"Voter_{i}")
        csr = v.generate_certificate_request()
        v.set_certificate(mun_s.sign_voter_csr(csr))
        enc_req = v.request_ballot(ae_pk)
        blank, sig = ea_s.receive_ballot_request(enc_req, pd_s)
        v.receive_blank_ballot(blank, sig, ae_pk)
        payload = v.submit_ballot(choice, ae_pk, pk_as)
        ea_s.receive_encrypted_ballot(payload, v.get_public_key(), pk_as)
    t_vote = (time.perf_counter() - t_vote_start) * 1000
    print(f" {t_vote:.0f} ms")

    # Fase di scrutinio
    t_tally_start = time.perf_counter()
    result = sa_s.tally_votes(ea_s.bulletin_board, ae_pk)
    t_tally = (time.perf_counter() - t_tally_start) * 1000

    # Verifica universale
    t_vu_start = time.perf_counter()
    ScrutinyAuthority.verify_tally(result["signed_payload"], result["as_signature"], pk_as)
    ScrutinyAuthority.verify_ballot_consistency(result["signed_payload"], ea_s.bulletin_board)
    t_vu = (time.perf_counter() - t_vu_start) * 1000

    total = t_tally + t_vu
    per_ballot = t_tally / n_voters

    print(f"  {n_voters:>4d} elettori:")
    print(f"       Scrutinio (verifica+decifrazione+conteggio): {t_tally:>10.2f} ms  "
          f"({per_ballot:.2f} ms/scheda)")
    print(f"       Verifica universale:                  {t_vu:>10.2f} ms")
    print(f"       TOTALE scrutinio + VU:                       {total:>10.2f} ms")
    print(f"       Risultato: SI={result['count_si']}, NO={result['count_no']}, "
          f"NULLO={result['count_null']}")
    print(f"       Payload pubblicato: {len(result['signed_payload']):,d} bytes "
          f"({len(result['signed_payload']) / 1024:.1f} KB)")

print(f"\n{'=' * 70}")
print(f"  Benchmark scrutinio completato.")
print(f"{'=' * 70}")