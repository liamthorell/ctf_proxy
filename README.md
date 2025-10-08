# How to CTF Proxy

Så nu kommer du får lära dig hur du använder [ctf_proxy](https://github.com/ByteLeMani/ctf_proxy).

## Vad är det???

"Ingen vet" - Martin. "Jag vet dock lite" - Lian. ctf_proxy kan vi använda för att patcha services på ett lätt sätt. Alla nätverkspacket kommer gå igenom ctf_proxy och vi kan då antingen blocka/skicka vidare paketet.

## Hur funkar det?

Alla patches görs genom python funktioner som vi skriver i specifika filer. Dessa filer kommer ligga i `/XXX/ctf_proxy/proxy/filter_modules/SERVICE_NAME/` där kommer det finnas en `SERVICE_NAME_IN.py` och en `SERVICE_NAME_OUT.py`. `SERVICE_NAME_IN.py` kommer köras innan paketet skickas vidare till servicen och `SERVICE_NAME_OUT.py` kommer köras efter att packetet lämnat servicen. Oftast är det `..._IN.py` som vi kommer använda.

## Filstruktur

```
- /XXX/ctf_proxy/proxy/filter_modules/
    - SERVICE_NAME/
        - SERVICE_NAME_IN.py
        - SERVICE_NAME_OUT.py
    - SERVICE_NAME_2/
        - SERVICE_NAME_2_IN.py
        - SERVICE_NAME_2_OUT.py
    - SERVICE_NAME_3/
        - SERVICE_NAME_3_IN.py
        - SERVICE_NAME_3_OUT.py
```

Dessa filer kommer innehålla en klass där vi kan skapa funktioner. Oavsätt namn på dessa funktioner så kommer de att köras.

## Hur skapar jag en patch?

Du går in i en filter-fil och skapar en funktion. Denna funktion kommer att köras för varje paket som går igenom ctf_proxy. Om funktionen returnerar `True` så kommer paketet att **blockas**. Om funktionen returnerar `False` så kommer paketet att skickas vidare.

Alltså: `True=BLOCK` och `False=ALLOW`

Nedan är ett exempel på en filter-fil:

```python
class Module():
    # HTTP Example
    def curl(self, stream: HTTPStream):
        """block curl user-agent"""
        message = stream.current_http_message
        return "curl" in message.headers.get("user-agent")

    # TCP Example
    def password(self, stream: TCPStream):
        """block passwords longer than 10 characters"""
        if b"Insert password:" in stream.previous_messages[0] and len(stream.current_message.strip()) > 10:
            return True # block
        return False # allow

    # other examples are in the example_functions.py file

    def execute(self, stream: Stream):
        # Do not touch
        # ...
```

Man kan skapa oänligt många funktioner och alla kommer att köras för varje paket. Jag rekommenderar att kolla i [example_functions.py (github länk)](https://github.com/liamthorell/ctf_proxy/blob/main/proxy/filter_modules/example_functions.py) för fler exempel på filter-funktioner.

## Vad händer om jag pajar nått och gör så att python filen errorar?

Ja det som händer då är att alla paket kommer att "allowas" och inte blockas.

## Hur sparar/deployar jag mina patches?

Du sparar filen. Proxyn använder sig av hot-reloading så den updaterar filterna när du sparar filter-filerna.

## Åh nej nått går snett, hur debuggar jag?

Du kan gå in i `/root/services/ctf_proxy/` och köra `docker compose logs` för att se outputen från ctf_proxy. Där kanske det står ett använtbart felmeddelande.
