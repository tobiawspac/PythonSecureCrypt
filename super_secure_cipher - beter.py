import os
from base64 import b64encode, b64decode
import zlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512, HMAC
import hashlib # Pro další hašování
import secrets # Pro robustnější generování soli pro master klíč
import hmac # Pro zabezpečené porovnání HMAC

class DecryptionError(Exception):
    """Vlastní výjimka pro chyby při dešifrování."""
    pass

# Funkce pro bezpečné vymazání dat z paměti
def secure_wipe(data):
    """
    Pokusí se přepsat citlivá data nulami v paměti.
    Funguje nejlépe pro `bytearray` objekty.
    Pro neměnné typy (`bytes`, `str`) pouze smaže referenci,
    aby umožnil garbage collectoru dříve zasáhnout.
    """
    if isinstance(data, bytearray):
        # Přepište bajty nulami
        for i in range(len(data)):
            data[i] = 0
    elif isinstance(data, bytes) or isinstance(data, str):
        # Nelze přepsat, ale můžeme smazat referenci
        # Pythonův GC to pak může vyčistit.
        pass # Del se provede automaticky při ukončení funkce, kde je reference


class SuperSecureCipher:
    """
    Třída pro extrémně zabezpečené třívrstvé šifrování a dešifrování textu.
    Využívá AES-256 GCM, vícenásobné, vysoce iterované PBKDF2 pro odvození klíčů,
    kryptografické hashe pro integritu dat i ověření hesla, kompresi a robustní validaci.
    """
    def __init__(self):
        # Nastavení konstant pro PBKDF2 iterace - extrémně vysoké pro max. odolnost proti hrubé síle
        # V PRODUKCI TESTUJTE VÝKON! Tyto hodnoty mohou být VELMI pomalé na slabších systémech.
        self.PBKDF2_ITERATIONS_MASTER = 3_000_000 # Zvýšeno
        self.PBKDF2_ITERATIONS_LAYER = 2_500_000   # Zvýšeno

        # Délky klíčů v bajtech
        self.KEY_LENGTH = 32  # AES-256
        self.SALT_LENGTH = 16 # Doporučená délka soli
        self.NONCE_LENGTH = 16 # Délka Nonce pro AES GCM (pevně dáno standardem pro 128 bit nonce)
        self.TAG_LENGTH = 16 # Délka autentizačního tagu (pevně dáno standardem pro GCM)
        self.MASTER_PASSWORD_SALT_LENGTH = 32 # Delší sůl pro hlavní heslo pro extra odolnost

        # Konstantní sůl pro odvození hlavního klíče z hesla - pro pevné zabezpečení
        # V PRAXI by se neměla používat PŘÍMO tato konstanta, pokud aplikace podporuje více uživatelů.
        # Spíše by měla být odvozena z unikátního ID uživatele + nějaké globální (bezpečné) konstanty,
        # nebo generována a uložena per-user (což jde proti "nokey" přístupu zde).
        # Pro účely tohoto příkladu je to ale vylepšením oproti žádné pevné soli.
        self._master_salt_base = b"SuperSecureCipherMasterSaltBaseValue!@#$"

    def _derive_master_key(self, password: str, salt: bytes) -> bytes:
        """
        Odvozuje hlavní klíč z hesla a unikátní soli pomocí PBKDF2.
        Používá velmi vysoký počet iterací a SHA512.
        """
        password_bytes = bytearray(password.encode('utf-8')) # Heslo jako bytearray pro vymazání
        
        derived_salt = HMAC.new(self._master_salt_base, salt, digestmod=SHA512).digest()
        
        # PBKDF2 vrátí bytes, převedeme na bytearray pro potenciální vymazání
        master_key_ba = bytearray(
            PBKDF2(password_bytes, derived_salt,
                   dkLen=self.KEY_LENGTH, count=self.PBKDF2_ITERATIONS_MASTER,
                   hmac_hash_module=SHA512)
        )
        secure_wipe(password_bytes) # Okamžitě vymaž heslo z paměti

        return bytes(master_key_ba) # Vrátit jako neměnné bytes, protože Crypto.Cipher očekává bytes

    def _derive_layer_key(self, master_key: bytes, salt: bytes) -> bytes:
        """
        Odvozuje klíč pro jednotlivé šifrovací vrstvy z master klíče a unikátní soli.
        """
        # Master_key je zde bytes, PBKDF2 ho může zpracovat.
        # Klíč vrstvy vrátíme jako bytes.
        derived_layer_key = PBKDF2(master_key, salt,
                                   dkLen=self.KEY_LENGTH, count=self.PBKDF2_ITERATIONS_LAYER,
                                   hmac_hash_module=SHA512)
        return derived_layer_key

    def encrypt(self, plaintext: str, password: str) -> str:
        """
        Šifruje zprávu ve třech vrstvách pomocí AES-256 GCM.
        Zahrnuje:
        - Kompresi dat
        - Hash původního plaintextu pro ověření integrity (MAC)
        - Autentizační hash hesla pro rychlou kontrolu při dešifrování
        - Bezpečné vymazání klíčů z paměti
        """
        if not plaintext or not password:
            raise ValueError("Plaintext a heslo nesmí být prázdné.")

        master_key_salt = get_random_bytes(self.MASTER_PASSWORD_SALT_LENGTH)
        master_key = None # Inicializace pro finally blok pro vymazání
        layer_keys = [] # Seznam pro uložení klíčů vrstev pro bezpečné vymazání

        try:
            master_key = self._derive_master_key(password, master_key_salt)

            # Autentizační hash hesla (MAC) - ověřuje heslo bez pokusu o plné dešifrování
            password_auth_tag = HMAC.new(master_key, b"PASSWORD_AUTHENTICATION", digestmod=SHA512).digest()

            # Komprese a hash původního plaintextu
            compressed_plaintext = zlib.compress(plaintext.encode('utf-8'), level=zlib.Z_BEST_COMPRESSION)
            plaintext_integrity_hash = SHA512.new(plaintext.encode('utf-8')).digest()

            # Data pro šifrování v první vrstvě: auth_tag + integrity_hash + compressed_plaintext
            data_to_encrypt_first_layer = password_auth_tag + plaintext_integrity_hash + compressed_plaintext

            encrypted_parts = []
            current_data = data_to_encrypt_first_layer

            # --- Třívrstvé šifrování ---
            for _ in range(3):
                salt = get_random_bytes(self.SALT_LENGTH)
                key = self._derive_layer_key(master_key, salt)
                layer_keys.append(key) # Uložit klíč pro vymazání

                cipher = AES.new(key, AES.MODE_GCM)
                ciphertext, tag = cipher.encrypt_and_digest(current_data)
                nonce = cipher.nonce

                encrypted_parts.extend([b64encode(salt), b64encode(nonce), b64encode(tag)])
                current_data = ciphertext # Výstup jedné vrstvy je vstupem další

            encrypted_parts.append(b64encode(current_data)) # Přidáme finální ciphertext

            # Přidáme sůl master klíče na začátek serializace
            final_encrypted_data = b'.'.join([b64encode(master_key_salt)] + encrypted_parts).decode('utf-8')
            
            return final_encrypted_data
        finally:
            # Zde vymazat všechny klíče vrstev a master klíč, i když dojde k chybě
            for key in layer_keys:
                secure_wipe(bytearray(key)) # Převedeme na bytearray pro vymazání
            if master_key:
                secure_wipe(bytearray(master_key))

    def decrypt(self, encrypted_data: str, password: str) -> str:
        """
        Dešifruje zprávu ve třech vrstvách.
        Zahrnuje:
        - Ověření hesla pomocí autentizačního hashe
        - Ověření integrity původního plaintextu
        - Dekompresi dat
        - Důkladné zpracování chyb
        - Bezpečné vymazání klíčů z paměti
        """
        if not encrypted_data or not password:
            raise DecryptionError("Zašifrovaná zpráva a heslo nesmí být prázdné.")

        master_key = None # Inicializace pro finally blok pro vymazání
        layer_keys = [] # Seznam pro uložení klíčů vrstev pro bezpečné vymazání

        try:
            components = encrypted_data.split('.')
            
            # Očekáváme 1 (master_key_salt) + 3 * (salt, nonce, tag) + 1 (final_ciphertext) = 1 + 9 + 1 = 11 komponent
            if len(components) != 11:
                raise DecryptionError("Neplatný formát zašifrovaných dat. Chybí komponenty.")

            # Extrahujeme master_key_salt
            master_key_salt = b64decode(components[0])
            if len(master_key_salt) != self.MASTER_PASSWORD_SALT_LENGTH:
                raise DecryptionError("Neplatná délka soli pro hlavní klíč.")

            master_key = self._derive_master_key(password, master_key_salt)

            # Ověření hesla před dešifrováním vrstev
            expected_password_auth_tag = HMAC.new(master_key, b"PASSWORD_AUTHENTICATION", digestmod=SHA512).digest()

            # --- Třívrstvé dešifrování ---
            current_ciphertext = b64decode(components[-1]) # Poslední komponenta je finální ciphertext

            decrypted_layers_data = [] # Budeme ukládat data po dešifrování každé vrstvy
            
            for i in range(2, -1, -1): # Iterujeme od poslední vrstvy (3) k první (1)
                # Komponenty pro aktuální vrstvu: [1 + i*3 + 1] -> salt, [1 + i*3 + 2] -> nonce, [1 + i*3 + 3] -> tag
                salt = b64decode(components[1 + i*3])
                nonce = b64decode(components[1 + i*3 + 1])
                tag = b64decode(components[1 + i*3 + 2])

                # Důslednější kontrola délek
                if len(salt) != self.SALT_LENGTH or \
                   len(nonce) != self.NONCE_LENGTH or \
                   len(tag) != self.TAG_LENGTH:
                    raise DecryptionError(f"Neplatná délka salt/nonce/tag pro vrstvu {i+1}. Možná poškozená data nebo špatné heslo.")

                key = self._derive_layer_key(master_key, salt)
                layer_keys.append(key) # Uložit klíč pro vymazání
                
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                
                try:
                    decrypted_data = cipher.decrypt_and_verify(current_ciphertext, tag)
                    decrypted_layers_data.append(decrypted_data)
                    current_ciphertext = decrypted_data # Výstup je vstupem další vrstvy
                except ValueError as e:
                    # Toto je klíčové: ValueError z decrypt_and_verify obvykle znamená špatný klíč nebo tag.
                    raise DecryptionError(f"Autentizační selhání v šifrovací vrstvě {i+1}. Špatné heslo nebo poškozená data.") from e

            # Po dešifrování všech vrstev, získáme data z první vrstvy (poslední v `decrypted_layers_data` listu)
            final_decrypted_data = decrypted_layers_data[-1]

            # Oddělíme autentizační hash hesla a integritní hash plaintextu
            received_password_auth_tag = final_decrypted_data[:len(expected_password_auth_tag)]
            plaintext_integrity_hash_received = final_decrypted_data[len(expected_password_auth_tag):len(expected_password_auth_tag) + SHA512.digest_size]
            compressed_plaintext = final_decrypted_data[len(expected_password_auth_tag) + SHA512.digest_size:]

            # --- Klíčové ověření hesla (MAC) ---
            # Používáme hmac.compare_digest pro odolnost proti timing attacks
            if not hmac.compare_digest(expected_password_auth_tag, received_password_auth_tag):
                raise DecryptionError("Zadané heslo je nesprávné. Autentizace selhala.")

            # Dekomprese dat
            plaintext_bytes = zlib.decompress(compressed_plaintext)
            plaintext = plaintext_bytes.decode('utf-8')

            # --- Ověření integrity původního plaintextu ---
            recalculated_plaintext_hash = SHA512.new(plaintext_bytes).digest()
            if not hmac.compare_digest(plaintext_integrity_hash_received, recalculated_plaintext_hash):
                raise DecryptionError("Integrita původního plaintextu selhala! Data byla změněna nebo jsou poškozena.")

            return plaintext

        except zlib.error as e:
            raise DecryptionError(f"Chyba při dekompresi dat: {e}. Pravděpodobně poškozená data nebo špatné heslo.") from e
        except (ValueError, TypeError, IndexError) as e:
            # Zachytí chyby jako neplatné Base64, špatná délka klíče/nonce/tag atd.
            raise DecryptionError(
                f"Obecná chyba při dešifrování: {e}. Pravděpodobně špatné heslo, poškozená/neplatná data nebo neúplná zpráva."
            ) from e
        except Exception as e:
            # Zachytí jakékoli neočekávané chyby a zabrání pádu aplikace
            raise DecryptionError(f"Nastala neočekávaná chyba při dešifrování: {e}") from e
        finally:
            # Zde vymazat všechny klíče vrstev a master klíč, i když dojde k chybě
            for key in layer_keys:
                secure_wipe(bytearray(key))
            if master_key:
                secure_wipe(bytearray(master_key))

# Příklad použití (pro testování mimo Flask - s konzolovým menu):
if __name__ == "__main__":
    cipher = SuperSecureCipher()

    while True:
        print("\n--- Ultra Zabezpečená Šifra (Konzole) ---")
        print("1. Šifrovat zprávu")
        print("2. Dešifrovat zprávu")
        print("3. Konec")
        
        choice = input("Zadejte volbu (1-3): ")

        if choice == '1':
            print("\n--- Šifrování ---")
            plaintext = input("Zadejte zprávu k zašifrování: ")
            password = input("Zadejte silné heslo (bez něj zprávu nedešifrujete!): ")
            try:
                encrypted_text = cipher.encrypt(plaintext, password)
                print("\n✅ Zašifrovaná zpráva (zkopírujte celou!):")
                print(encrypted_text)
            except ValueError as e:
                print(f"❌ Chyba: {e}")
            except Exception as e:
                print(f"❌ Neočekávaná chyba při šifrování: {e}")

        elif choice == '2':
            print("\n--- Dešifrování ---")
            encrypted_data = input("Vložte celou zašifrovanou zprávu: ")
            password = input("Zadejte heslo použité při šifrování: ")
            try:
                decrypted_text = cipher.decrypt(encrypted_data, password)
                print("\n✅ Dešifrovaná zpráva:")
                print(decrypted_text)
            except DecryptionError as e:
                print(f"❌ Chyba dešifrování: {e}")
            except Exception as e:
                print(f"❌ Neočekávaná chyba při dešifrování: {e}")

        elif choice == '3':
            print("Děkujeme za použití šifry. Na shledanou!")
            break
        else:
            print("Neplatná volba. Zadejte prosím číslo od 1 do 3.")