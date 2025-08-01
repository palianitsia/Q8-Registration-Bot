import sys
import requests
import random
import string
import time
import re
import logging
from urllib.parse import urljoin
import datetime
from bs4 import BeautifulSoup

# ===== LOGGING CONFIGURATION =====
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('q8_bot.log', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# ===== CONFIGURATION =====
# Mail.tm API configuration
MAILTM_BASE_URL = "https://api.mail.tm"

# SMS verification service configuration
SMS_API_KEY = "SOSTITUISCI_CON_LA_TUA_CHIAVE"
SMS_BASE_URL = "https://sms-verification-number.com/stubs/handler_api"
SERVICE_CODE = "kt"  # Q8 service code
COUNTRY_CODE = "86"  # Italy

# Q8 Website configuration
Q8_BASE_URL = "https://www.q8.it"
REGISTRATION_URL = f"{Q8_BASE_URL}/clubq8-areariservata/registrazione"
INVITE_URL = "https://www.q8.it/clubq8-areariservata/public/invita-amici/UTENTE" - # tuo codice
RECAPTCHA_SITEKEY = "6Ld3mAEqAAAAAKskB4zM1qqAlnHffn1uBrDKWY6d"
CAPTCHA_API_KEY = "SOSTITUISCI_CON_LA_TUA_CHIAVE"

# Default values
DEFAULT_PASSWORD = "LAPASS" # SCEGLI LA TUA PASS PREDEFINITA
DEFAULT_CITY = "ROMA"
DEFAULT_GENDER = "M"

# Headers
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "it-IT,it;q=0.8,en-US;q=0.5,en;q=0.3",
    "Content-Type": "application/x-www-form-urlencoded",
    "X-Requested-With": "XMLHttpRequest"
}

# ===== UTILITY FUNCTIONS =====
def random_string(length=10):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))

def generate_random_person():
    """Generate random Italian personal data"""
    first_names = ["Marco", "Luca", "Giovanni", "Andrea", "Francesco", "Alessandro", 
                  "Matteo", "Stefano", "Roberto", "Paolo", "Filippo", "Simone"]
    last_names = ["Rossi", "Bianchi", "Russo", "Ferrari", "Esposito", "Romano", 
                 "Colombo", "Ricci", "Marino", "Greco", "Bruno", "Gallo"]
    
    birth_date = datetime.date(
        year=random.randint(1960, 2000),
        month=random.randint(1, 12),
        day=random.randint(1, 28)
    )
    
    return {
        "nome": random.choice(first_names),
        "cognome": random.choice(last_names),
        "data_nascita": birth_date.strftime("%d/%m/%Y"),
        "sesso": DEFAULT_GENDER,
        "comune_nascita": DEFAULT_CITY,
        "cellulare": None
    }

# ===== TEMPORARY EMAIL FUNCTIONS =====
def get_domain():
    r = requests.get(f"{MAILTM_BASE_URL}/domains")
    return r.json()["hydra:member"][0]["domain"]

def create_account():
    email = f"{random_string()}@{get_domain()}"
    password = random_string(12)
    logger.info(f"Creating account: {email}")

    r = requests.post(f"{MAILTM_BASE_URL}/accounts", json={"address": email, "password": password})
    if r.status_code == 201:
        logger.info("Account created!")
    elif "exists" in r.text:
        logger.warning("Account already exists, retrying...")
        return create_account()
    else:
        logger.error(f"Error: {r.text}")
        return None, None, None

    token = get_token(email, password)
    return email, password, token

def get_token(email, password):
    r = requests.post(f"{MAILTM_BASE_URL}/token", json={"address": email, "password": password})
    if r.status_code == 200:
        return r.json()["token"]
    else:
        logger.error("Unable to get token.")
        return None

def get_messages(token):
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(f"{MAILTM_BASE_URL}/messages", headers=headers)
    return r.json()["hydra:member"]

def read_message(token, message_id):
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(f"{MAILTM_BASE_URL}/messages/{message_id}", headers=headers)
    return r.json()

def wait_for_confirmation_email(token, timeout=120):
    logger.info(f"Waiting for confirmation email... (timeout: {timeout} seconds)")
    
    for _ in range(timeout):
        try:
            messages = get_messages(token)
            if messages:
                logger.info(f"Received {len(messages)} messages.")
                q8_email_found = False
                for msg in messages:
                    message_data = read_message(token, msg['id'])
                    
                    subject = message_data.get('subject', 'No subject')
                    sender = message_data.get('from', {}).get('address', 'No sender')
                    logger.info(f"Checking email - Subject: {subject}, Sender: {sender}")
                    
                    subject_lower = subject.lower()
                    if any(keyword in subject_lower for keyword in [
                        "q8", "conferma", "confirm", "email", "registrazione", "verifica"
                    ]) and "mail.tm" not in subject_lower and "welcome" not in subject_lower:
                        logger.info("Q8 confirmation email found.")
                        logger.info(f"Subject: {subject}")
                        
                        html_content = message_data.get('html', '')
                        text_content = message_data.get('text', '')
                        
                        logger.debug(f"[DEBUG HTML] Type: {type(html_content)}, Content: {html_content[:1000]}")
                        logger.debug(f"[DEBUG TEXT] Type: {type(text_content)}, Content: {str(text_content)[:1000]}")
                        
                        if not isinstance(html_content, str):
                            logger.warning(f"html_content is {type(html_content)}, converting to string.")
                            html_content = str(html_content)
                        
                        if html_content:
                            soup = BeautifulSoup(html_content, 'html.parser')
                            for a in soup.find_all('a', href=True):
                                link_text = a.get_text(strip=True).upper()
                                href = a['href']
                                logger.debug(f"Analyzing HTML link: {link_text} | {href}")
                                if (
                                    'CONFERMA' in link_text 
                                    or 'q8' in href.lower()
                                    or 'awstrack.me' in href.lower()
                                ):
                                    logger.info(f"Confirmation link found (HTML): {href}")
                                    return process_aws_redirect(href)
                        
                        if not isinstance(text_content, str):
                            logger.warning(f"text_content is {type(text_content)}, converting to string.")
                            if isinstance(text_content, list):
                                def flatten(lst):
                                    result = []
                                    for item in lst:
                                        if isinstance(item, list):
                                            result.extend(flatten(item))
                                        else:
                                            result.append(str(item))
                                    return result
                                text_content = ' '.join(flatten(text_content))
                            else:
                                text_content = str(text_content)
                            logger.debug(f"[DEBUG CONVERTED TEXT] {text_content[:4000]}")
                        
                        if isinstance(text_content, str):
                            url_patterns = [
                                r'https://[^\s"\'>]*q8\.it[^\s"\'>]*',
                                r'https://[^\s"\'>]*q8\.com[^\s"\'>]*',
                                r'https://[^\s"\'>]*awstrack\.me[^\s"\'>]*'
                            ]
                            for pattern in url_patterns:
                                for match in re.finditer(pattern, text_content):
                                    confirmation_url = match.group(0)
                                    logger.info(f"Confirmation link found (TEXT): {confirmation_url}")
                                    return process_aws_redirect(confirmation_url)
                        else:
                            logger.error(f"Cannot process text_content, invalid type after conversion: {type(text_content)}")
                        
                        logger.warning("No confirmation link found in this Q8 email.")
                        q8_email_found = True
                    else:
                        logger.info("Email is not a Q8 confirmation email.")
                
                if not q8_email_found:
                    logger.warning("No Q8 email found in received messages, retrying...")
            else:
                logger.warning("No messages received yet.")
            
            time.sleep(1)
        except Exception as e:
            logger.error(f"Error checking emails: {str(e)}")
            time.sleep(1) 
    
    logger.error("Timeout: no confirmation email received.")
    return None


def process_aws_redirect(url):
    """Handle AWS tracking links and return final URL"""
    if 'awstrack.me' not in url:
        return url
        
    try:
        logger.info(f"Processing AWS tracking link: {url}")
        session = requests.Session()
        
        response = session.head(url, headers=HEADERS, allow_redirects=False, timeout=15)
        
        if 300 <= response.status_code < 400:
            redirect_url = response.headers.get('Location', '')
            logger.info(f"Extracted redirect URL: {redirect_url}")
            
            decoded_url = requests.utils.unquote(redirect_url)
            
            if '%2F' in decoded_url or '%3F' in decoded_url:
                decoded_url = requests.utils.unquote(decoded_url)
            
            logger.info(f"Final confirmation URL: {decoded_url}")
            return decoded_url
        else:
            logger.warning(f"Unexpected response status: {response.status_code}")
            return url
    except Exception as e:
        logger.error(f"Error processing AWS redirect: {str(e)}")
        return url

# ===== SMS VERIFICATION FUNCTIONS =====
def get_temp_number():
    logger.info("Requesting temporary number...")
    params = {
        "api_key": SMS_API_KEY,
        "action": "getNumber",
        "service": SERVICE_CODE,
        "operator": "any",
        "country": COUNTRY_CODE
    }

    start_time = time.time()
    while time.time() - start_time < 60:
        response = requests.get(SMS_BASE_URL, params=params)
        r = response.text.strip()
        if "ACCESS_NUMBER" in r:
            _, op_id, phone_number = r.split(":")
            phone_number = phone_number[-10:] if phone_number.startswith("39") else phone_number
            logger.info(f"Number received: {phone_number} (ID: {op_id})")
            return op_id, phone_number
        elif r == "NO_NUMBERS":
            logger.info("No numbers available, waiting...")
            time.sleep(5)
        else:
            raise Exception(f"Error in number request: {r}")

    raise TimeoutError("Timeout: no numbers available within 60 seconds.")

def get_sms_code(op_id):
    logger.info("Waiting for SMS code...")
    params = {
        "api_key": SMS_API_KEY,
        "action": "getStatus",
        "id": op_id
    }

    start_time = time.time()
    while time.time() - start_time < 120:  # 2 minutes timeout
        response = requests.get(SMS_BASE_URL, params=params)
        r = response.text.strip()
        
        if "STATUS_OK" in r:
            code = r.split(":")[1]
            logger.info(f"SMS code received: {code}")
            return code
        elif r == "STATUS_WAIT_CODE":
            logger.info("Waiting for code...")
            time.sleep(5)
        else:
            raise Exception(f"Error in SMS status: {r}")
    
    raise TimeoutError("Timeout: no SMS code received within 2 minutes.")

# ===== CAPTCHA FUNCTIONS =====
def solve_captcha():
    logger.info("Sending request to 2Captcha...")
    try:
        params = {
            "key": CAPTCHA_API_KEY,
            "method": "userrecaptcha",
            "googlekey": RECAPTCHA_SITEKEY,
            "pageurl": INVITE_URL,
            "json": 1,
            "invisible": 1,
            "version": "v3",
            "action": "submit",
            "min_score": 0.7,
            "soft_id": 2987
        }

        start_time = time.time()
        response = requests.get("http://2captcha.com/in.php", params=params, timeout=10)
        response.raise_for_status()
        r = response.json()
        
        if r.get("status") != 1:
            raise Exception(f"2Captcha error: {r.get('request', 'Unknown error')}")
        
        captcha_id = r["request"]
        logger.info(f"CAPTCHA ID: {captcha_id} - Waiting for solution...")

        while time.time() - start_time < 180:
            time.sleep(3)
            res = requests.get("http://2captcha.com/res.php", params={
                "key": CAPTCHA_API_KEY,
                "action": "get",
                "id": captcha_id,
                "json": 1
            }, timeout=10).json()
            
            if res.get("status") == 1:
                logger.info("CAPTCHA solved")
                return res["request"]
            elif res.get("request") != "CAPCHA_NOT_READY":
                raise Exception(f"CAPTCHA error: {res.get('request', 'Unknown error')}")
        
        raise TimeoutError("Timeout after 180 seconds")
    except Exception as e:
        logger.error(f"CAPTCHA solving error: {str(e)}")
        raise

# ===== CODICE FISCALE FUNCTIONS =====
def genera_codice_fiscale(nome, cognome, data_nascita, sesso, comune):
    pari = {
        **{str(i): i for i in range(10)},
        **dict(zip("ABCDEFGHIJKLMNOPQRSTUVWXYZ", range(0, 26)))
    }
    dispari = {
        **dict(zip("0123456789", [1, 0, 5, 7, 9, 13, 15, 17, 19, 21])),
        **dict(zip("ABCDEFGHIJKLMNOPQRSTUVWXYZ",
                   [1, 0, 5, 7, 9, 13, 15, 17, 19, 21,
                    2, 4, 18, 20, 11, 3, 6, 8, 12, 14,
                    16, 10, 22, 25, 24, 23]))
    }
    controllo = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    mesi = "ABCDEHLMPRST"
    
    codici_catastali = {
        "ROMA": "H501"
    }

    def normalizza_nome(nome):
        nome = nome.upper().replace(" ", "")
        return ''.join(c for c in nome if c.isalpha())

    def codice_nome(nome, tipo="nome"):
        nome = normalizza_nome(nome)
        consonanti = ''.join(c for c in nome if c not in 'AEIOU')
        vocali = ''.join(c for c in nome if c in 'AEIOU')

        if tipo == "nome" and len(consonanti) >= 4:
            codice = consonanti[0] + consonanti[2] + consonanti[3]
        else:
            codice = (consonanti + vocali + "XXX")[:3]
        return codice

    def codice_data_sesso(data, sesso):
        anno = str(data.year)[-2:]
        mese = mesi[data.month - 1]
        giorno = data.day + 40 if sesso.upper() == "F" else data.day
        return f"{anno}{mese}{giorno:02d}"

    def calcola_carattere_controllo(cf_parziale):
        somma = 0
        for i, c in enumerate(cf_parziale):
            if (i + 1) % 2 == 0:
                somma += pari[c]
            else:
                somma += dispari[c]
        return controllo[somma % 26]

    codice = ""
    codice += codice_nome(cognome, "cognome")
    codice += codice_nome(nome, "nome")
    
    if isinstance(data_nascita, str):
        try:
            data_nascita = datetime.datetime.strptime(data_nascita, "%d/%m/%Y").date()
        except ValueError:
            data_nascita = datetime.datetime.strptime(data_nascita, "%Y-%m-%d").date()
    
    codice += codice_data_sesso(data_nascita, sesso)
    comune = "ROMA"  
    codice += codici_catastali.get(comune, "H501")  
    codice += calcola_carattere_controllo(codice)
    return codice


# ===== Q8 REGISTRATION FUNCTIONS =====
def extract_csrf_token(session, url):
    logger.info(f"Extracting CSRF token from {url}...")
    try:
        response = session.get(url, headers=HEADERS, timeout=10)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        csrf_input = soup.find('input', {'name': '_csrfToken'})
        if csrf_input:
            token = csrf_input.get('value')
            logger.info(f"CSRF token found: {token[:10]}...")
            return token
        
        patterns = [
            r'name="_csrfToken"\s+value="(.+?)"',
            r'<meta\s+name="csrf-token"\s+content="(.+?)"'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, response.text)
            if match:
                token = match.group(1)
                logger.info(f"CSRF token found (regex): {token[:10]}...")
                return token
        
        raise Exception("CSRF token not found with any method")
    except Exception as e:
        logger.error(f"Error extracting CSRF token: {str(e)}")
        raise

def submit_invitation(session, phone_number):
    logger.info("Submitting invitation form...")
    
    for attempt in range(3):
        logger.info(f"Attempt {attempt + 1} of 3")
        try:
            csrf_token = extract_csrf_token(session, INVITE_URL)
            if not csrf_token:
                logger.error("Failed to get CSRF token")
                continue
                
            if attempt > 0:
                session.cookies.clear()
                session.get(Q8_BASE_URL)
                
            captcha_token = solve_captcha()
            
            headers = {
                **HEADERS,
                "Origin": Q8_BASE_URL,
                "Referer": INVITE_URL,
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "X-Requested-With": "XMLHttpRequest",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin"
            }

            data = {
                "g-recaptcha-response": captcha_token,
                "_csrfToken": csrf_token,
                "cellulare": phone_number
            }

            time.sleep(random.uniform(1, 3))
            
            response = session.post(
                INVITE_URL,
                headers=headers,
                data=data,
                allow_redirects=False,
                timeout=20
            )

            logger.info(f"Status Code: {response.status_code}")
            logger.info(f"Response Text: {response.text[:200]}...")

            if "invalid" in response.text.lower() or "recaptcha" in response.text.lower():
                logger.error("Server rejected CAPTCHA, retrying with new token...")
                continue  
            
            if response.status_code == 303:
                location = response.headers.get('Location', '')
                if '/clubq8-areariservata/info' in location:
                    logger.info("Invitation successful!")
                    return True
                logger.warning(f"Unexpected redirect: {location}")
            elif response.status_code == 200:
                logger.warning("Possible success but needs verification")
                return True
            else:
                logger.error(f"Unexpected response: {response.status_code}")

            if attempt < 2:
                retry_delay = random.randint(5, 10)
                logger.info(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)

        except Exception as e:
            logger.error(f"Attempt {attempt + 1} failed: {str(e)}")
            if attempt < 2:
                time.sleep(5)

    logger.error("All invitation attempts failed")
    return False


def submit_registration(session, email, password, person_data, cf):
    logger.info("Submitting registration form...")
    try:
        csrf_token = extract_csrf_token(session, REGISTRATION_URL)
        
        verify_url = f"{Q8_BASE_URL}/clubq8-areariservata/verifica-presenza-email"
        verify_data = {
            "_csrfToken": csrf_token,
            "captchatoken": "", 
            "email": email
        }
        
        response = session.post(
            verify_url,
            headers={**HEADERS, "Referer": REGISTRATION_URL},
            data=verify_data,
            allow_redirects=True
        )
        
        if response.status_code != 200:
            logger.error(f"Email verification failed: {response.status_code}")
            return False
        
        registration_data = {
            "_csrfToken": csrf_token,
            "email": email,
            "userId": "",
            "social": "false",
            "password": password,
            "confirmPassword": password,
            "nome": person_data["nome"],
            "cognome": person_data["cognome"],
            "sesso": person_data["sesso"],
            "codiceFiscale": cf,
            "dataNascita": person_data["data_nascita"],
            "comuneNascita": person_data["comune_nascita"],
            "cellulare": person_data["cellulare"]
        }
        
        response = session.post(
            f"{Q8_BASE_URL}/clubq8-areariservata/registrazione-dati",
            headers={**HEADERS, "Referer": f"{Q8_BASE_URL}/clubq8-areariservata/registrazione-dati"},
            data=registration_data,
            allow_redirects=True
        )
        
        if response.status_code != 200:
            logger.error(f"Registration submission failed: {response.status_code}")
            return False
        
        privacy_url = f"{Q8_BASE_URL}/clubq8-areariservata/registrazione-fine"
        privacy_data = {
            "_csrfToken": csrf_token,
            "consensoObbligatorio": "S",
            "_consensoObbligatorio": "on",
            "consensoMarketing": "S",
            "consensoProfilazione": "S",
            "consensoTerzeParti": "S",
            "flagClub": "S",
            "flagLoyalty": "S"
        }
        
        response = session.post(
            privacy_url,
            headers={**HEADERS, "Referer": f"{Q8_BASE_URL}/clubq8-areariservata/accettazione-privacy"},
            data=privacy_data,
            allow_redirects=True
        )
        
        if response.status_code == 200:
            logger.info("Registration completed successfully!")
            return True
        else:
            logger.error(f"Privacy acceptance failed: {response.status_code}")
            return False
            
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        return False

# ===== MAIN PROCESS =====
def main(num_registrations=1):
    logger.info("🚀 Starting Q8 registration process...")
    start_time = time.time()
    
    successful_registrations = 0
    
    for i in range(num_registrations):
        logger.info(f"\n=== STARTING REGISTRATION {i+1}/{num_registrations} ===")
        registration_start = time.time()
        
        with requests.Session() as session:
            try:
                session.headers.update(HEADERS)
                session.max_redirects = 3
                session.timeout = 15
                
                logger.info("Requesting temporary number...")
                try:
                    op_id, phone_number = get_temp_number()
                    logger.info(f"Number received: {phone_number} (ID: {op_id})")
                except Exception as e:
                    logger.error(f"Failed to get phone number: {str(e)}")
                    raise
                
                if not submit_invitation(session, phone_number):
                    raise Exception("Invitation process failed after multiple attempts")
                
                logger.info("Creating temporary email...")
                try:
                    email, email_password, mail_token = create_account()
                    if not mail_token:
                        raise Exception("Failed to get email token")
                    logger.info(f"Email created: {email}")
                except Exception as e:
                    logger.error(f"Email creation failed: {str(e)}")
                    raise
                
                person_data = generate_random_person()
                person_data["cellulare"] = phone_number
                logger.info(f"Generated person data: {person_data}")
                
                cf = genera_codice_fiscale(
                    person_data["nome"],
                    person_data["cognome"],
                    person_data["data_nascita"],
                    person_data["sesso"],
                    person_data["comune_nascita"]
                )
                logger.info(f"Codice Fiscale: {cf}")
                
                if not submit_registration(session, email, DEFAULT_PASSWORD, person_data, cf):
                    raise Exception("Registration form submission failed")
                
                confirmation_url = wait_for_confirmation_email(mail_token)
                if not confirmation_url:
                    raise Exception("No confirmation email received")
                
                logger.info(f"Confirmation URL: {confirmation_url}")
                
                response = session.get(confirmation_url, headers=HEADERS)
                if response.status_code == 200:
                    logger.info("Email confirmed successfully!")
                else:
                    logger.error(f"Email confirmation failed: {response.status_code}")
                
                sms_code = get_sms_code(op_id)

                with open('accounts.txt', 'a', encoding='utf-8') as f:
                    f.write(f"{email}:{DEFAULT_PASSWORD}:{sms_code}\n")
                logger.info("Credentials saved to accounts.txt")
                
                logger.info("\n🎉 REGISTRATION COMPLETED SUCCESSFULLY!")
                logger.info("="*50)
                logger.info(f"📧 Email: {email}")
                logger.info(f"🔑 Password: {DEFAULT_PASSWORD}")
                logger.info(f"📱 Phone: {phone_number}")
                logger.info(f"🔢 SMS Code: {sms_code}")
                logger.info(f"🧑 Personal Data: {person_data}")
                logger.info(f"🔢 Codice Fiscale: {cf}")
                logger.info("="*50)
                
                successful_registrations += 1
                
            except Exception as e:
                logger.error(f"\n❌❌❌ REGISTRATION FAILED ❌❌❌")
                logger.error(f"Error: {str(e)}")
                logger.error("Debug Info:")
                logger.error(f"- Session Cookies: {session.cookies.get_dict()}")
                logger.error(f"- Last URL: {getattr(session, 'last_url', 'N/A')}")
            finally:
                registration_time = time.time() - registration_start
                logger.info(f"\n⏱ Registration time: {registration_time:.2f} seconds")
                if registration_time > 60:
                    logger.warning("Warning: Registration took longer than 1 minute")
                
                if i < num_registrations - 1:
                    delay = random.randint(10, 30)
                    logger.info(f"Waiting {delay} seconds before next registration...")
                    time.sleep(delay)
    
    total_time = time.time() - start_time
    logger.info(f"\n=== FINAL REPORT ===")
    logger.info(f"Total registrations attempted: {num_registrations}")
    logger.info(f"Successful registrations: {successful_registrations}")
    logger.info(f"Success rate: {successful_registrations/num_registrations*100:.2f}%")
    logger.info(f"Total execution time: {total_time:.2f} seconds")
    logger.info(f"Average time per registration: {total_time/num_registrations:.2f} seconds")
    
    return successful_registrations > 0

if __name__ == "__main__":
    print("\nQ8 Registration Bot")
    print("===================")
    print("Digita 'avvia (numero)' per iniziare le registrazioni")
    print("Esempio: 'avvia 10' per fare 10 registrazioni")
    print("Digita 'esci' per terminare il programma")
    
    while True:
        try:
            user_input = input("\nComando: ").strip().lower()
            if user_input == "esci":
                print("Terminating program.")
                break
            elif user_input.startswith("avvia"):
                try:
                    parts = user_input.split()
                    num_registrations = int(parts[1]) if len(parts) > 1 else 1
                    if num_registrations < 1:
                        print("Il numero di registrazioni deve essere maggiore di 0.")
                        continue
                    logger.info(f"Starting {num_registrations} registrations...")
                    success = main(num_registrations)
                    print(f"\nRegistrazione completata. Successo: {success}")
                    print(f"Controlla 'q8_bot.log' per i dettagli.")
                except ValueError:
                    print("Formato non valido. Esempio: 'avvia 5'")
                except Exception as e:
                    logger.error(f"Errore durante l'esecuzione: {str(e)}")
                    print(f"Errore: {str(e)}. Controlla 'q8_bot.log' per i dettagli.")
            else:
                print("Comando non riconosciuto. Usa 'avvia (numero)' o 'esci'")
        except KeyboardInterrupt:
            print("\nInterruzione ricevuta. Vuoi terminare? (s/n)")
            if input().strip().lower() == 's':
                print("Terminating program.")
                break
        except Exception as e:
            logger.error(f"Errore critico: {str(e)}")
            print(f"Errore critico: {str(e)}. Il programma continua a eseguire.")