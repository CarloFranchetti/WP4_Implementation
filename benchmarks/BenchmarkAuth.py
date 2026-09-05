"""
Benchmark of the electronic voting protocol's authentication phase.
Measures:
  - Computational cost of cryptographic operations
  - Size of exchanged messages (DER)
  - Latency of verification operations
  - End-to-end interaction times
"""
import time
import statistics

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.x509.oid import NameOID

from archive.PublicDirectory import PublicDirectory
from entities.Voter import Voter
from entities.ElectoralAuthority import ElectoralAuthority
from entities.ScrutinyAuthority import ScrutinyAuthority
from pki.StateCA import StateCA
from pki.MunicipalityCA import MunicipalityCA


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
        "result": result
    }


def cert_der_size(cert):
    """Certificate size in DER format (bytes)."""
    return len(cert.public_bytes(serialization.Encoding.DER))


def csr_der_size(csr):
    """CSR size in DER format (bytes)."""
    return len(csr.public_bytes(serialization.Encoding.DER))


def print_header(title):
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}")


def print_metric(m):
    print(f"  {m['label']:.<50s} {m['mean_ms']:8.2f} ms  "
          f"(med: {m['median_ms']:.2f}, σ: {m['stdev_ms']:.2f}, "
          f"min: {m['min_ms']:.2f}, max: {m['max_ms']:.2f})")


# =====================================================================
# 1. COMPUTATIONAL COST OF CRYPTOGRAPHIC OPERATIONS
# =====================================================================
print_header("1. COMPUTATIONAL COST — Cryptographic Operations")

# --- Key Generation ---
print("\n  [RSA Key Generation]")
m_keygen_4096 = measure(
    lambda: rsa.generate_private_key(public_exponent=65537, key_size=4096),
    "RSA-4096 key generation", iterations=5
)
print_metric(m_keygen_4096)

m_keygen_2048 = measure(
    lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
    "RSA-2048 key generation", iterations=10
)
print_metric(m_keygen_2048)

# --- CSR Signing ---
print("\n  [CSR Signing (creating signed CSR)]")
key_4096 = rsa.generate_private_key(public_exponent=65537, key_size=4096)
key_2048 = rsa.generate_private_key(public_exponent=65537, key_size=2048)

m_csr_sign_4096 = measure(
    lambda: x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test")])
    ).sign(key_4096, hashes.SHA256()),
    "CSR sign (RSA-4096 + SHA-256)", iterations=20
)
print_metric(m_csr_sign_4096)

m_csr_sign_2048 = measure(
    lambda: x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test")])
    ).sign(key_2048, hashes.SHA256()),
    "CSR sign (RSA-2048 + SHA-256)", iterations=20
)
print_metric(m_csr_sign_2048)

# --- Certificate Signing (by CA) ---
print("\n  [X.509 Certificate Signing (CA issuance)]")
state_ca_bench = StateCA("BenchmarkCA")
csr_bench = x509.CertificateSigningRequestBuilder().subject_name(
    x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TestEntity")])
).sign(key_4096, hashes.SHA256())

m_cert_sign_authority = measure(
    lambda: state_ca_bench.sign_authority_csr(csr_bench),
    "Cert sign — authority (RSA-4096 CA -> end-entity)", iterations=20
)
print_metric(m_cert_sign_authority)

m_cert_sign_municipality = measure(
    lambda: state_ca_bench.sign_municipality_csr(csr_bench),
    "Cert sign — municipality (RSA-4096 CA -> sub-CA)", iterations=20
)
print_metric(m_cert_sign_municipality)

csr_voter_bench = x509.CertificateSigningRequestBuilder().subject_name(
    x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TestVoter")])
).sign(key_2048, hashes.SHA256())
municipality_bench = MunicipalityCA("BenchMunicipality", state_ca_bench)

m_cert_sign_voter = measure(
    lambda: municipality_bench.sign_voter_csr(csr_voter_bench),
    "Cert sign — voter (RSA-4096 CA -> end-entity 2048)", iterations=20
)
print_metric(m_cert_sign_voter)

# --- Certificate Signature Verification ---
print("\n  [Certificate signature verification]")
cert_ea_bench = state_ca_bench.sign_authority_csr(csr_bench)
root_pub = state_ca_bench.certificate.public_key()

m_verify_cert = measure(
    lambda: root_pub.verify(
        cert_ea_bench.signature,
        cert_ea_bench.tbs_certificate_bytes,
        PKCS1v15(),
        cert_ea_bench.signature_hash_algorithm
    ),
    "Cert verify (RSA-4096 pubkey, PKCS1v15, SHA-256)", iterations=100
)
print_metric(m_verify_cert)

cert_voter_bench = municipality_bench.sign_voter_csr(csr_voter_bench)
municipality_pub = municipality_bench.certificate.public_key()

m_verify_voter = measure(
    lambda: municipality_pub.verify(
        cert_voter_bench.signature,
        cert_voter_bench.tbs_certificate_bytes,
        PKCS1v15(),
        cert_voter_bench.signature_hash_algorithm
    ),
    "Cert verify voter (RSA-4096 pubkey verifies 2048 cert)", iterations=100
)
print_metric(m_verify_voter)


# =====================================================================
# 2. SIZE OF EXCHANGED MESSAGES
# =====================================================================
print_header("2. SIZE OF EXCHANGED MESSAGES (DER format)")

# Real setup for measurements
state_ca = StateCA("Italy")
municipality = MunicipalityCA("Vietri Sul Mare", state_ca)
ea = ElectoralAuthority("National Electoral Authority", state_ca)
sa = ScrutinyAuthority("National Scrutiny Authority", state_ca)
voter = Voter("Peppe")

csr_voter = voter.generate_certificate_request()
cert_voter = municipality.sign_voter_csr(csr_voter)
voter.set_certificate(cert_voter)

# Voter's CSR
csr_ea = x509.CertificateSigningRequestBuilder().subject_name(
    x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "National Electoral Authority")])
).sign(rsa.generate_private_key(public_exponent=65537, key_size=4096), hashes.SHA256())

csr_ca = x509.CertificateSigningRequestBuilder().subject_name(
    x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "National Scrutiny Authority")])
).sign(rsa.generate_private_key(public_exponent=65537, key_size=4096), hashes.SHA256())

csr_municipality = x509.CertificateSigningRequestBuilder().subject_name(
    x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Vietri Sul Mare")])
).sign(rsa.generate_private_key(public_exponent=65537, key_size=4096), hashes.SHA256())

print(f"\n  {'Message':.<50s} {'Bytes':>8s}")
print(f"  {'-' * 60}")
print(f"  {'StateCA Certificate (root, self-signed)':.<50s} {cert_der_size(state_ca.certificate):>8d} bytes")
print(f"  {'MunicipalityCA Certificate':.<50s} {cert_der_size(municipality.certificate):>8d} bytes")
print(f"  {'AE Certificate':.<50s} {cert_der_size(ea.certificate):>8d} bytes")
print(f"  {'CA Certificate':.<50s} {cert_der_size(sa.certificate):>8d} bytes")
print(f"  {'Voter Certificate':.<50s} {cert_der_size(voter.certificate):>8d} bytes")
print(f"  {'-' * 60}")
print(f"  {'Municipality CSR (RSA-4096)':.<50s} {csr_der_size(csr_municipality):>8d} bytes")
print(f"  {'AE CSR (RSA-4096)':.<50s} {csr_der_size(csr_ea):>8d} bytes")
print(f"  {'CA CSR (RSA-4096)':.<50s} {csr_der_size(csr_ca):>8d} bytes")
print(f"  {'Voter CSR (RSA-2048)':.<50s} {csr_der_size(csr_voter):>8d} bytes")

# Total exchanged
total_setup = (cert_der_size(state_ca.certificate) +
               csr_der_size(csr_municipality) + cert_der_size(municipality.certificate) +
               csr_der_size(csr_ea) + cert_der_size(ea.certificate) +
               csr_der_size(csr_ca) + cert_der_size(sa.certificate))
total_voter = csr_der_size(csr_voter) + cert_der_size(voter.certificate)

print(f"\n  {'TOTAL setup (one-time)':.<50s} {total_setup:>8d} bytes")
print(f"  {'TOTAL per voter':.<50s} {total_voter:>8d} bytes")


# =====================================================================
# 3. VERIFICATION OPERATION LATENCY
# =====================================================================
print_header("3. VERIFICATION OPERATION LATENCY")

pd = PublicDirectory()
pd.set_root_ca(state_ca.certificate)
pd.add_municipality(municipality.certificate)
pd.add_authority(ea.certificate)
pd.add_authority(sa.certificate)

print("\n  [Single certificate verification]")
m_v_ea = measure(
    lambda: pd.verify_certificate(ea.certificate),
    "Verify AE cert (StateCA signature)", iterations=100
)
print_metric(m_v_ea)

m_v_ca = measure(
    lambda: pd.verify_certificate(sa.certificate),
    "Verify CA cert (StateCA signature)", iterations=100
)
print_metric(m_v_ca)

m_v_municipality = measure(
    lambda: pd.verify_certificate(municipality.certificate),
    "Verify Municipality cert (StateCA signature)", iterations=100
)
print_metric(m_v_municipality)

print("\n  [Full chain verification (Voter → Municipality → StateCA)]")
m_v_chain = measure(
    lambda: pd.verify_certificate_chain(voter.certificate, municipality.certificate),
    "Full chain verification (2 checks)", iterations=100
)
print_metric(m_v_chain)

print("\n  [Voter-side verification (verify_authority_certificate)]")
m_v_voter_ea = measure(
    lambda: voter.verify_authority_certificate("National Electoral Authority", pd),
    "Voter verifies AE cert", iterations=100
)
print_metric(m_v_voter_ea)

m_v_voter_ca = measure(
    lambda: voter.verify_authority_certificate("National Scrutiny Authority", pd),
    "Voter verifies CA cert", iterations=100
)
print_metric(m_v_voter_ca)

# Fake cert verification
fake_state = StateCA("Fake State")
fake_ea = ElectoralAuthority("Fake AE", fake_state)
pd.add_authority(fake_ea.certificate)

m_v_fake = measure(
    lambda: pd.verify_certificate(fake_ea.certificate),
    "Verify FAKE cert (must fail)", iterations=100
)
print_metric(m_v_fake)


# =====================================================================
# 4. END-TO-END INTERACTION TIMES
# =====================================================================
print_header("4. END-TO-END INTERACTION TIMES")

print("\n  [Phase 0 — PKI Setup (StateCA + MunicipalityCA)]")
m_setup = measure(
    lambda: (StateCA("Italy"), None)[0],
    "Create StateCA (keygen + self-signed cert)", iterations=5
)
print_metric(m_setup)

sca_tmp = StateCA("Italy")
m_mun = measure(
    lambda: MunicipalityCA("Municipality", sca_tmp),
    "Create MunicipalityCA (keygen + CSR + sign)", iterations=5
)
print_metric(m_mun)

print("\n  [FASE 1 - Authorities Creation]")
m_ea_create = measure(
    lambda: ElectoralAuthority("AE", sca_tmp),
    "Create AE (keygen + CSR + sign)", iterations=5
)
print_metric(m_ea_create)

m_ca_create = measure(
    lambda: ScrutinyAuthority("AS", sca_tmp),
    "Create AS (keygen + CSR + sign)", iterations=5
)
print_metric(m_ca_create)

print("\n  [FASE 5 — Voter Registration (keygen + CSR + sign)]")


def register_voter():
    v = Voter("Test")
    csr = v.generate_certificate_request()
    cert = municipality.sign_voter_csr(csr)
    v.set_certificate(cert)
    return v


m_voter_reg = measure(register_voter, "Full voter registration", iterations=10)
print_metric(m_voter_reg)

print("\n  [Full single voter flow (AE/CA verify + registration + chain verify)]")


def full_voter_flow():
    v = Voter("Test")
    # Verify AE and CA
    v.verify_authority_certificate("National Electoral Authority", pd)
    v.verify_authority_certificate("National Scrutiny Authority", pd)
    # Registration
    csr = v.generate_certificate_request()
    cert = municipality.sign_voter_csr(csr)
    v.set_certificate(cert)
    # Verify chain
    pd.verify_certificate_chain(v.certificate, municipality.certificate)
    return v


m_full = measure(full_voter_flow, "Full single voter flow", iterations=10)
print_metric(m_full)

# =====================================================================
# 5. SCALABILITY — Simulation with N voters
# =====================================================================
print_header("5. SCALABILITY — Simulation with N voters")

for n_voters in [10, 50, 100]:
    start = time.perf_counter()
    for i in range(n_voters):
        v = Voter(f"Voter_{i}")
        v.verify_authority_certificate("National Electoral Authority", pd)
        v.verify_authority_certificate("National Scrutiny Authority", pd)
        csr = v.generate_certificate_request()
        cert = municipality.sign_voter_csr(csr)
        v.set_certificate(cert)
        pd.verify_certificate_chain(v.certificate, municipality.certificate)
    elapsed = (time.perf_counter() - start) * 1000
    avg = elapsed / n_voters
    print(f"  {n_voters:>4d} voters: {elapsed:>10.2f} ms total, {avg:>8.2f} ms/voter")

print(f"\n{'=' * 70}")
print(f"  Benchmark completed.")
print(f"{'=' * 70}")

