# Q8-Registration-Bot
automatizza il processo di registrazione al programma fedeltà Q8

Ottenimento di un numero di telefono temporaneo per la verifica SMS

Creazione di un indirizzo email temporaneo

Generazione di dati personali casuali (nome, cognome, data di nascita)

Calcolo del codice fiscale italiano valido

Risoluzione automatica del CAPTCHA

Invio del modulo di registrazione

Conferma via email e SMS

I dati degli account creati con successo vengono salvati nel file accounts.txt.

Dipendenze necessarie
Librerie Python
Installa le seguenti dipendenze con pip install -r requirements.txt:

requests>=2.31.0
beautifulsoup4>=4.12.2
python-dateutil>=2.8.2


Servizi esterni richiesti
API Mail.tm - Per la creazione di email temporanee (gratuito)

Servizio SMS verification - Richiede una chiave API per numeri telefonici temporanei

2Captcha - Servizio a pagamento per la risoluzione automatica di reCAPTCHA

Configurazione necessaria
Prima di eseguire lo script, è necessario configurare:

Chiave API per il servizio SMS (SMS_API_KEY)

Chiave API per 2Captcha (CAPTCHA_API_KEY)

Password predefinita per gli account (DEFAULT_PASSWORD)

URL di invito personale (INVITE_URL)

Utilizzo
Eseguire lo script e inserire il comando:

avvia N per creare N account (es. avvia 5)

esci per terminare il programma

I log dettagliati vengono salvati in q8_bot.log.

dev by palianitsia

PACE ✌️


