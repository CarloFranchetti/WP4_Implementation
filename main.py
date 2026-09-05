"""
Simulazione del protocollo di voto elettronico.

Fasi:
  0. PKI Setup (StateCA, MunicipalityCA)
  1. Creazione Autorità (AE, CA)
  2. Pubblicazione certificati nel PublicDirectory
  3. Elettore verifica i certificati delle autorità
  4. Security test — Autorità con CA fasulla
  5. Autenticazione elettore (MunicipalityCA → certificato)
  6. Protocollo di invio scheda di voto (referendum SI/NO)
     + Security tests: double voting, firma manomessa, CA non registrata
"""

import base64 as _b64

from cryptography.hazmat._oid import NameOID

from archive.PublicDirectory import PublicDirectory
from entities.Voter import Voter
from entities.ElectoralAuthority import ElectoralAuthority, InvalidBallotRequest, InvalidBallotSubmission
from entities.ScrutinyAuthority import ScrutinyAuthority
from pki.StateCA import StateCA
from pki.MunicipalityCA import MunicipalityCA

# ============================================================
# FASE 0: PKI Setup
# ============================================================
print("=" * 60)
print("FASE 0: PKI Setup")
print("=" * 60)

state_ca = StateCA("Italy")
print(f"StateCA '{state_ca.common_name}' creato (certificato autofirmato)")

municipality = MunicipalityCA("Cetara", state_ca)
print(f"MunicipalityCA '{municipality.common_name}' creato (certificato firmato da StateCA)")

# ============================================================
# FASE 1: Creazione delle autorità (AE e AS)
# ============================================================
print("\n" + "=" * 60)
print("FASE 1: Creazione dell'Autorità Elettorale (AE) e dell'Autorità di Scrutinio (AS)")
print("=" * 60)

ea = ElectoralAuthority("National Electoral Authority", state_ca)
print(f"AE '{ea.common_name}' creato (certificato firmato da StateCA, ca=False)")

sa = ScrutinyAuthority("National Scrutiny Authority", state_ca)
print(f"AS '{sa.common_name}' creato (certificato firmato da StateCA, ca=False)")

# ============================================================
# FASE 2: Pubblicazione del certificato nell'annuario pubblico
# ============================================================
print("\n" + "=" * 60)
print("FASE 2: Pubblicazione del certificato nell'annuario pubblico")
print("=" * 60)

pd = PublicDirectory()

pd.set_root_ca(state_ca.certificate)
print(f"Root CA '{state_ca.common_name}' settata")

pd.add_municipality(municipality.certificate)
print(f"il certificato di '{municipality.common_name}' pubblicato nel registro")

pd.add_authority(ea.certificate)
print(f"Certificato AE '{ea.common_name}' pubblicato nel registro")

pd.add_authority(sa.certificate)
print(f"Certificato AS '{sa.common_name}' pubblicato nel registro")

# ============================================================
# PHASE 3: L'elettore verifica i certificati AE e AS
# ============================================================
print("\n" + "=" * 60)
print("FASE 3: L'elettore verifica i certificati AE e AS")
print("=" * 60)

voter = Voter("Peppe")
print(f"Voter '{voter.name}' creato")

ea_valid = voter.verify_authority_certificate("National Electoral Authority", pd)
if ea_valid:
    print(f"Voter '{voter.name}': Certificato AE verificato con successo (firma StateCA valida)")
else:
    print(f"Voter '{voter.name}': Certificato AE NON VALIDO!")

as_valid = voter.verify_authority_certificate("National Scrutiny Authority", pd)
if as_valid:
    print(f"Voter '{voter.name}': Certificato CA verificato con successo (firma StateCA valida)")
else:
    print(f"Voter '{voter.name}': Certificato CA NON VALIDO!")

# ============================================================
# FASE 4: Security test (Fake Authority)
# ============================================================
print("\n" + "=" * 60)
print("FASE 4: Security Test — Autorità con finta CA")
print("=" * 60)

fake_state = StateCA("Fake State")
fake_ea = ElectoralAuthority("Fake AE", fake_state)
print(f"Falso account AE creato: '{fake_ea.common_name}' (signed by '{fake_state.common_name}')")

pd.add_authority(fake_ea.certificate)
print(f"Certificato AE falso pubblicato nel registro")

fake_ea_valid = voter.verify_authority_certificate("Fake AE", pd)
if fake_ea_valid:
    print(f"ERRORE DI SICUREZZA: è stato accettato un certificato AE falso!")
else:
    print(f"Certificato AE falso RIFIUTATO: la firma non corrisponde a quella del certificato StateCA legittimo")

# ============================================================
# FASE 5: Voter Authentication
# ============================================================
print("\n" + "=" * 60)
print("FASE 5: Autenticazione degli elettori tramite il Comune")
print("=" * 60)

csr = voter.generate_certificate_request()
certificate = municipality.sign_voter_csr(csr)
voter.set_certificate(certificate)
print(f"Voter '{voter.name}' ha ricevuto il certificato da '{municipality.common_name}'")

issuer_name = voter.certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
municipality_cert = pd.get_municipality(issuer_name)

if pd.verify_certificate_chain(voter.certificate, municipality_cert):
    print(f"CATENA VERIFICATA CORRETTAMENTE")
else:
    print(f"CATENA NON RISPETTATA CORRETTAMENTE")

# ============================================================
# FASE 6: Sottomissione Scheda
# Referendum: "Sei favorevole alla proposta di legge X?" (SI / NO)
# ============================================================
print("\n" + "=" * 60)
print("FASE 6: Sottomissione Scheda — Referendum SI/NO")
print("=" * 60)

# L'elettore recupera pkAS dal PublicDirectory (certificati delle autorità sono pubblici)
pk_as = pd.get_authority_public_key("National Scrutiny Authority")
pk_ae  = ea.get_public_key()

# ----------------------------------------------------------
# Passo 1 — Richiesta scheda:  Enc(pkAE, ballot_request || Cert_elettore)
# ----------------------------------------------------------
print("\n[Passo 1] Elettore -> AE : Enc(pkAE, ballot_request || Cert_elettore)")
encrypted_request = voter.request_ballot(pk_ae)
print(f"Richiesta cifrata inviata ({len(encrypted_request)} byte)")

# ----------------------------------------------------------
# Passi 2-3 — AE verifica la catena -> (schedavuota, σ_AE)
# ----------------------------------------------------------
print("\n[Passi 2-3] AE verifica catena -> AE -> Elettore : (schedavuota, σ_AE)")
try:
    blank_ballot_bytes, ae_signature = ea.receive_ballot_request(encrypted_request, pd)
    print(f"Catena certificato elettore verificata (Voter -> MunicipalityCA -> StateCA)")
    print(f"Scheda vuota firmata da AE inviata all'elettore")
except InvalidBallotRequest as exc:
    print(f"Richiesta rifiutata: {exc}")
    raise SystemExit(1)

# L'elettore verifica la firma AE sulla scheda vuota
blank_ballot = voter.receive_blank_ballot(blank_ballot_bytes, ae_signature, pk_ae)
print(f"Elettore ha verificato σ_AE sulla scheda vuota")
print(f"Quesito referendario: \"{blank_ballot.question}\"")

# ----------------------------------------------------------
# Passo 4 — Compilazione e invio scheda
#   schedacifrata        = Enc(pkAS, ballot)          [RSA-OAEP, dim. fissa]
#   schedacifratacifrata = Enc(pkAE, schedacifrata ‖ voter_id)   [cifratura ibrida]
#   σ                    = Sign(skEletore, schedacifratacifrata)
#
#   Messaggio: <IDelettore, schedacifratacifrata, σ>
# ----------------------------------------------------------
choice = "SI"
print(f"\n[Passo 4] Elettore → AE : <IDelettore, Enc(pkAE, Enc(pkAS, ballot) ‖ ID), σ_elettore>")
print(f"  Scelta: '{choice}'")
submission_payload = voter.submit_ballot(choice, pk_ae, pk_as)
print(f"Payload di invio costruito")

# ----------------------------------------------------------
# Passi 5-7 — AE valida, registra e rilascia ricevuta
# ----------------------------------------------------------
print("\n[Passi 5-7] AE: verifica σ -> controlla ID consumati -> registra -> ricevuta")
try:
    receipt = ea.receive_encrypted_ballot(submission_payload, voter.get_public_key(), pk_as)
    print(f"Vrfy(pkEletore, encrypted_payload, σ) = 1")
    print(f"ID elettore non presente nella lista 'consumati'")
    print(f"Dimensione crittogramma AS corretta ({sa.get_public_key().key_size // 8} byte)")
    print(f"ID aggiunto alla lista 'consumati'")
    print(f"Scheda pubblicata su Bulletin Board B  ({len(ea.bulletin_board)} voce/voci)")
    print(f"Ricevuta: Sign(skAE, Hash(Enc(pkAS, ballot)))  ->  {len(receipt)} byte")
except InvalidBallotSubmission as exc:
    print(f"Invio rifiutato: {exc}")
    raise SystemExit(1)

# L'elettore verifica la ricevuta
receipt_valid = voter.verify_receipt(receipt, pk_ae)
print(f"\n  {'corretto' if receipt_valid else 'sbagliato'} Verifica ricevuta: "
      f"{'valida — voto registrato correttamente' if receipt_valid else 'NON VALIDA!'}")

# ----------------------------------------------------------
# Security Test A — Double voting
# ----------------------------------------------------------
print("\n" + "-" * 50)
print("Security Test A: Tentativo di voto doppio")
print("-" * 50)
try:
    ea.receive_encrypted_ballot(submission_payload, voter.get_public_key(), pk_as)
    print("ERRORE DI SICUREZZA: voto doppio accettato!")
except InvalidBallotSubmission as exc:
    print(f"Voto doppio RIFIUTATO: {exc}")

# ----------------------------------------------------------
# Security Test B — Firma manomessa
# ----------------------------------------------------------
print("\n" + "-" * 50)
print("Security Test B: Firma manomessa sull'invio")
print("-" * 50)

# Secondo elettore (diverso voter_id → nessun blocco per double-voting)
voter2 = Voter("Mario")
csr2 = voter2.generate_certificate_request()
voter2.set_certificate(municipality.sign_voter_csr(csr2))

tampered_payload = voter2.submit_ballot("NO", pk_ae, pk_as)
# Corrompe il primo byte della firma (base64-decodificata)
raw_sig = _b64.b64decode(tampered_payload["signature"])
corrupted_sig = bytes([raw_sig[0] ^ 0xFF]) + raw_sig[1:]
tampered_payload["signature"] = _b64.b64encode(corrupted_sig).decode()

try:
    ea.receive_encrypted_ballot(tampered_payload, voter2.get_public_key(), pk_as)
    print("ERRORE DI SICUREZZA: firma manomessa accettata!")
except InvalidBallotSubmission as exc:
    print(f"Firma manomessa RIFIUTATA: {exc}")

# ----------------------------------------------------------
# Security Test C — MunicipalityCA non registrata nel PublicDirectory
# ----------------------------------------------------------
print("\n" + "-" * 50)
print("Security Test C: Elettore con certificato di CA non registrata")
print("-" * 50)

unknown_municipality = MunicipalityCA("Comune Sconosciuto", state_ca)  # non pubblicata in pd
voter3 = Voter("Hacker")
csr3 = voter3.generate_certificate_request()
voter3.set_certificate(unknown_municipality.sign_voter_csr(csr3))

forged_request = voter3.request_ballot(pk_ae)
try:
    ea.receive_ballot_request(forged_request, pd)
    print("ERRORE DI SICUREZZA: catena non valida accettata!")
except InvalidBallotRequest as exc:
    print(f"Richiesta RIFIUTATA: {exc}")

# ----------------------------------------------------------
# Registrazione di altri elettori per lo scrutinio multi-voto
# ----------------------------------------------------------
print("\n" + "-" * 50)
print("Registrazione elettori aggiuntivi per lo scrutinio")
print("-" * 50)

# Voter 2 — vota NO (voter2 è già creato nel Security Test B, ma non ha votato validamente)
voter2 = Voter("Mario")
csr2 = voter2.generate_certificate_request()
voter2.set_certificate(municipality.sign_voter_csr(csr2))
encrypted_request2 = voter2.request_ballot(pk_ae)
blank2, sig2 = ea.receive_ballot_request(encrypted_request2, pd)
voter2.receive_blank_ballot(blank2, sig2, pk_ae)
payload2 = voter2.submit_ballot("NO", pk_ae, pk_as)
receipt2 = ea.receive_encrypted_ballot(payload2, voter2.get_public_key(), pk_as)
print(f" '{voter2.name}' ha votato NO — ricevuta verificata: {voter2.verify_receipt(receipt2, pk_ae)}")

# Voter 4 — vota ASTENUTO
voter4 = Voter("Lucia")
csr4 = voter4.generate_certificate_request()
voter4.set_certificate(municipality.sign_voter_csr(csr4))
encrypted_request4 = voter4.request_ballot(pk_ae)
blank4, sig4 = ea.receive_ballot_request(encrypted_request4, pd)
voter4.receive_blank_ballot(blank4, sig4, pk_ae)
payload4 = voter4.submit_ballot("ASTENUTO", pk_ae, pk_as)
receipt4 = ea.receive_encrypted_ballot(payload4, voter4.get_public_key(), pk_as)
print(f" '{voter4.name}' ha votato ASTENUTO — ricevuta verificata: {voter4.verify_receipt(receipt4, pk_ae)}")

# Voter 5 — vota SI
voter5 = Voter("Giovanni")
csr5 = voter5.generate_certificate_request()
voter5.set_certificate(municipality.sign_voter_csr(csr5))
encrypted_request5 = voter5.request_ballot(pk_ae)
blank5, sig5 = ea.receive_ballot_request(encrypted_request5, pd)
voter5.receive_blank_ballot(blank5, sig5, pk_ae)
payload5 = voter5.submit_ballot("SI", pk_ae, pk_as)
receipt5 = ea.receive_encrypted_ballot(payload5, voter5.get_public_key(), pk_as)
print(f" '{voter5.name}' ha votato SI — ricevuta verificata: {voter5.verify_receipt(receipt5, pk_ae)}")

print(f"\nBulletin Board B contiene ora {len(ea.bulletin_board)} scheda/e")
print(f"ID consumati: {len(ea._consumed_ids)}")
print(f"Voti attesi: SI=2 (Peppe, Giovanni), NO=1 (Mario), ASTENUTO=1 (Lucia)")

# ============================================================
# FASE 7: Scrutinio e Conteggio dei Voti
# ============================================================
print("\n" + "=" * 60)
print("FASE 7: Scrutinio e Conteggio dei Voti")
print("=" * 60)

# ----------------------------------------------------------
# AS preleva la Bulletin Board pubblica di AE
# ----------------------------------------------------------
print("AS preleva le schede cifrate dalla Bulletin Board pubblica di AE")
print(f"Schede sulla Bulletin Board: {len(ea.bulletin_board)}")

# ----------------------------------------------------------
# Verifica, decifrazione e conteggio
# ----------------------------------------------------------
print("\nAS: Vrfy(pkAE, σ) -> Dec(skAS, scheda) -> conteggio")
tally_result = sa.tally_votes(ea.bulletin_board, ea.get_public_key())

print(f"\n  --- Risultati dello scrutinio ---")
print(f"Schede verificate e decifrate: {tally_result['total_valid']}")
print(f"Anomalie (firma AE invalida): {tally_result['total_anomalies']}")
print(f"Decifrature invalide: {tally_result['total_invalid']}")
print(f"\n Conteggio finale:")
print(f"     SI:       {tally_result['count_si']}")
print(f"     NO:       {tally_result['count_no']}")
print(f"     NULLO:    {tally_result['count_null']}")
print(f"     TOTALE:   {tally_result['total_valid']}")

# Verifica correttezza conteggio
assert tally_result["count_si"] == 2, f"Attesi 2 SI, ottenuti {tally_result['count_si']}"
assert tally_result["count_no"] == 1, f"Atteso 1 NO, ottenuti {tally_result['count_no']}"
assert tally_result["count_null"] == 1, f"Atteso 1 NULLO, ottenuti {tally_result['count_null']}"
assert tally_result["total_anomalies"] == 0, "Non ci dovrebbero essere anomalie"
print(f"\n Asserzioni di correttezza superate!")

# ----------------------------------------------------------
# Verifica universale
# ----------------------------------------------------------
print("\nVerifica Universale ")

# Verifica firma di AS sul risultato
sig_valid = ScrutinyAuthority.verify_tally(
    tally_result["signed_payload"],
    tally_result["as_signature"],
    sa.get_public_key(),
)
print(f"{'corretto' if sig_valid else 'sbagliato'} Vrfy(pkAS, σAS, payload) = {'1 — firma valida' if sig_valid else '0 — INVALIDA!'}")

# Confronto schede cifrate (Bulletin Board AE vs payload AS)
ballot_match = ScrutinyAuthority.verify_ballot_consistency(
    tally_result["signed_payload"],
    ea.bulletin_board,
)
print(f"  {'corretto --' if ballot_match else 'sbagliato --'} Confronto schede Bulletin Board AE - payload AS: "
      f"{'coerente — nessuna scheda aggiunta/rimossa' if ballot_match else 'INCOERENTE!'}")

# ----------------------------------------------------------
# Security Test D — Scheda fraudolenta iniettata nella Bulletin Board
# ----------------------------------------------------------
print("\n" + "-" * 50)
print("Security Test D: Scheda fraudolenta iniettata nella Bulletin Board")
print("-" * 50)

import os
# Costruiamo una scheda cifrata fasulla con firma AE inventata
fake_encrypted_ballot = os.urandom(512)  # 512 byte casuali
fake_ae_signature = os.urandom(512)      # firma fasulla

# Inietto nella Bulletin Board una copia con la scheda fraudolenta
tampered_board = list(ea.bulletin_board) + [{
    "encrypted_ballot": fake_encrypted_ballot,
    "ae_signature": fake_ae_signature,
}]

tally_tampered = sa.tally_votes(tampered_board, ea.get_public_key())

if tally_tampered["total_anomalies"] == 1:
    print(f"Scheda fraudolenta RILEVATA come anomalia")
    print(f"     Motivo: {tally_tampered['anomalies'][0]['reason']}")
    print(f"Conteggio non alterato: SI={tally_tampered['count_si']}, "
          f"NO={tally_tampered['count_no']}, NULLO={tally_tampered['count_null']}")
else:
    print(f"ERRORE DI SICUREZZA: scheda fraudolenta non rilevata!")

# ----------------------------------------------------------
# Security Test E — Manomissione del risultato pubblicato
# ----------------------------------------------------------
print("\n" + "-" * 50)
print("Security Test E: Manomissione del risultato firmato da AS")
print("-" * 50)

# Altero un byte del payload firmato
original_payload = tally_result["signed_payload"]
tampered_payload_bytes = bytearray(original_payload)
tampered_payload_bytes[10] ^= 0xFF  # flip di un byte
tampered_payload_bytes = bytes(tampered_payload_bytes)

tamper_detected = not ScrutinyAuthority.verify_tally(
    tampered_payload_bytes,
    tally_result["as_signature"],
    sa.get_public_key(),
)

if tamper_detected:
    print(f"Manomissione RILEVATA: Vrfy(pkAS, σAS, payload_alterato) = 0")
else:
    print(f"ERRORE DI SICUREZZA: manomissione non rilevata!")

# ============================================================
# Summary
# ============================================================
print("\n" + "=" * 60)
print("SUMMARY: Protocollo completato con successo")
print("=" * 60)
print(f"StateCA:       '{state_ca.common_name}'")
print(f"AE:            '{ea.common_name}' — cert verificato: {ea_valid}")
print(f"AS:            '{sa.common_name}' — cert verificato: {as_valid}")
print(f"Municipality:  '{municipality.common_name}'")
print(f"Elettori registrati: {len(ea._consumed_ids)}")
print(f"Bulletin Board B:     {len(ea.bulletin_board)} scheda/e pubblicata/e")
print(f"ID consumati:  {len(ea._consumed_ids)}")
print(f"\nRisultato scrutinio:")
print(f"SI:    {tally_result['count_si']}")
print(f"NO:    {tally_result['count_no']}")
print(f"NULLO: {tally_result['count_null']}")
print(f"\nVerifica universale: firma AS valida, schede coerenti")
print(f"Security Test D: scheda fraudolenta rilevata")
print(f"Security Test E: manomissione risultato rilevata")
print(f"\nTutte le fasi del protocollo completate con successo!")