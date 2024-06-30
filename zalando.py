# ------------------------------------------------------------------------------- #

import cloudscraper, json, time, config, random, tldextract, uuid, datetime, threading
from bs4 import BeautifulSoup as bs
from urllib.parse import urlparse, unquote
from bot.logs import console
from bot.akamai import cookies
from bot.proxies import proxies
from bot import read_settings, close
from dhooks import Webhook, Embed

# ------------------------------------------------------------------------------- #

class Zalando:

    # ------------------------------------------------------------------------------- #

    def __init__(self, session:cloudscraper.CloudScraper, **kwargs):

        self.store = 'Zalando'

        self.task_data = kwargs.get('task_data', None)
        
        self.settings_json = read_settings.read()

        self.discord_webhook = self.settings_json['DISCORD_WEBHOOK']
        self.error_delay = self.settings_json['ERROR_DELAY']
        self.checkout_delay = self.settings_json['CHECKOUT_DELAY']
        self.monitor_delay = self.settings_json['MONITOR_DELAY']

        self.checkouts = 0

        self.checkout_limit = self.task_data['CHECKOUT_LIMIT']

        try:
            self.error_delay = int(self.error_delay)
            self.checkout_delay = int(self.checkout_delay)
            self.monitor_delay = int(self.monitor_delay)
        except:
            self.error('Delays must be integers. Check your settings.csv file.')
            close.execute()

        try:
            self.checkout_limit = int(self.checkout_limit)
        except:
            self.error('Checkout limit must be integer. Check your tasks.csv file.')
            close.execute()

        self.pids = []
        self.selected = {}
        self.title = self.task_data['TASK_INPUT']
        self.img = None

        self.s = session
        self.s.trust_env = False
        self.s.verify = True
        self.s.proxies = proxies.get_proxy()

        threading.Thread(target=self.login_thread).start()

        self.login()
        self.check_cart()

    # ------------------------------------------------------------------------------- #

    def send_webhook(self):

        try:
            hook = Webhook(url=self.discord_webhook)
            embed = Embed(color=7185217, timestamp=True, description=None)
            embed.set_thumbnail(url=self.img)
            embed.set_title(title='Successful Checkout!', url=self.task_data['TASK_INPUT'])
            embed.add_field(name='Website', value=f"{self.store} {tldextract.extract(self.task_data['TASK_INPUT']).suffix.upper()}", inline=False)
            embed.add_field(name='Product', value=self.title, inline=False)
            embed.add_field(name='Size', value=self.selected['size'], inline=False)
            embed.add_field(name='Payment', value=self.task_data['TASK_PAYMENT_METHOD'], inline=False)
            if self.s.proxies != {}:
                embed.add_field(name='Proxy', value=f'||`{self.s.proxies["http"]}`||', inline=False)
        except:
            pass

        try:
            hook.send(embeds=embed)
        except:
            pass

    # ------------------------------------------------------------------------------- #

    def status(self, msg:str):

        console.status(f'[{self.store}-{self.task_data["TASK_ID"]}] {msg}')

    # ------------------------------------------------------------------------------- #

    def error(self, msg:str):

        console.error(f'[{self.store}-{self.task_data["TASK_ID"]}] {msg}')

    # ------------------------------------------------------------------------------- #

    def success(self, msg:str):

        console.success(f'[{self.store}-{self.task_data["TASK_ID"]}] {msg}')

    # ------------------------------------------------------------------------------- #

    def login_thread(self):
        while True:
            time.sleep(240)
            self.login()
            continue

    def login(self):

        if self.checkout_limit == 0:
            pass
        else:
            if self.checkouts >= self.checkout_limit:
                self.error('Checkout limit reached! Stopping task...')
                close.execute()
            else:
                pass

        self.status('Logging in...')

        try:
            home_request = self.s.get(
                url=f'https://{urlparse(self.task_data["TASK_INPUT"]).netloc}',
                timeout=15,
                headers={
                    'authority': urlparse(self.task_data['TASK_INPUT']).netloc,
                    'method': 'GET',
                    'path': self.task_data['TASK_INPUT'].split(urlparse(self.task_data['TASK_INPUT']).netloc)[1],
                    'scheme': 'https',
                    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                    'accept-encoding': 'utf-8',
                    'accept-language': 'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7',
                    'cache-control': 'no-cache',
                    'sec-fetch-dest': 'document',
                    'sec-fetch-mode': 'navigate',
                    'sec-fetch-site': 'same-origin',
                    'sec-fetch-user': '?1',
                    'user-agent': self.s.headers['User-Agent']
                }
            )
        except Exception as e:
            self.error(f'An exception occurred: [{e.__class__.__name__}]')
            self.s.proxies = proxies.get_proxy()
            time.sleep(self.error_delay)
            return self.login()

        if home_request.ok == False:
            self.error(f'Request failed: Status Code {home_request.status_code}')
            self.s.proxies = proxies.get_proxy()
            time.sleep(self.error_delay)
            return self.login()

        del self.s.cookies['_abck']

        abck_cookie = cookies.get_cookie(self.task_data['TASK_INPUT'])

        self.s.cookies.set(
            name='_abck',
            value=abck_cookie,
            path='/',
            domain=f'.{tldextract.extract(self.task_data["TASK_INPUT"]).domain}.{tldextract.extract(self.task_data["TASK_INPUT"]).suffix}'
        )

        try:
            login_request = self.s.post(
                url=f'https://{urlparse(self.task_data["TASK_INPUT"]).netloc}/api/reef/login',
                timeout=15,
                allow_redirects=False,
                json={
                    "username": self.task_data["WEBSITE_USERNAME"],
                    "password": self.task_data["WEBSITE_PASSWORD"],
                    "wnaMode": "modal"
                },
                headers={
                    'authority': urlparse(self.task_data['TASK_INPUT']).netloc,
                    'method': 'POST',
                    'path': '/api/reef/login',
                    'scheme': 'https',
                    'accept': 'application/json',
                    'accept-encoding': 'utf-8',
                    'accept-language': 'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7',
                    'cache-control': 'no-cache',
                    'content-type': 'application/json',
                    'dpr': '1',
                    'origin': f'https://{urlparse(self.task_data["TASK_INPUT"]).netloc}',
                    'referer': home_request.url,
                    'sec-fetch-dest': 'empty',
                    'sec-fetch-mode': 'cors',
                    'sec-fetch-site': 'same-origin',
                    'user-agent': self.s.headers['User-Agent'],
                    'viewport-width': '848',
                    'x-xsrf-token': self.s.cookies.get_dict()['frsx'],
                    'x-zalando-render-page-uri': str(home_request.url).split(urlparse(self.task_data["TASK_INPUT"]).netloc)[1],
                    'x-zalando-request-uri': str(home_request.url).split(urlparse(self.task_data["TASK_INPUT"]).netloc)[1]
                }
            )
        except Exception as e:
            self.error(f'An exception occurred: [{e.__class__.__name__}]')
            self.s.proxies = proxies.get_proxy()
            time.sleep(self.error_delay)
            return self.login()

        if login_request.ok == False and login_request.status_code != 401:
            self.error(f'Request failed: Status Code {login_request.status_code}')
            self.s.proxies = proxies.get_proxy()
            time.sleep(self.error_delay)
            return self.login()

        elif login_request.status_code == 401:
            self.error('Login credentials are invalid. Please check your tasks.csv file.')
            time.sleep(self.error_delay)
            return self.login()

        self.success('Successfully logged in!')

    # ------------------------------------------------------------------------------- #

    def check_cart(self):

        self.status('Checking cart...')

        try:
            r = self.s.get(
                url=f'https://{urlparse(self.task_data["TASK_INPUT"]).netloc}/cart/',
                timeout=15,
                headers={
                    'authority': urlparse(self.task_data['TASK_INPUT']).netloc,
                    'method': 'GET',
                    'path': '/cart/',
                    'scheme': 'https',
                    'accept': '*/*',
                    'accept-encoding': 'utf-8',
                    'accept-language': 'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7',
                    'cache-control': 'no-cache',
                    'dpr': '1',
                    'referer': f'https://{urlparse(self.task_data["TASK_INPUT"]).netloc}/',
                    'sec-fetch-dest': 'empty',
                    'sec-fetch-mode': 'cors',
                    'sec-fetch-site': 'same-origin',
                    'user-agent': self.s.headers['User-Agent'],
                }
            )
        except Exception as e:
            self.error(f'An exception occurred: [{e.__class__.__name__}]')
            self.s.proxies = proxies.get_proxy()
            time.sleep(self.error_delay)
            return self.check_cart()

        if r.ok == False:
            self.error(f'Request failed: Status Code {r.status_code}')
            self.s.proxies = proxies.get_proxy()
            time.sleep(self.error_delay)
            return self.check_cart()

        soup = bs(markup=r.text, features='lxml')

        for div in soup.find_all(name='div'):
            div_soup = bs(markup=str(div), features='lxml')

            try:
                cart_response = div_soup.find(name='div')['data-data']
                break
            except:
                continue

        try:
            cart_response = json.loads(unquote(str(cart_response)))
        except:
            self.error('Cart checking failed, retrying...')
            time.sleep(self.error_delay)
            return self.check_cart()

        try:
            cart_id = cart_response['cart']['id']
            articles = cart_response['cart']['groups'][0]['articles']
        except:
            self.success('No items in cart!')
            return self.monitor()

        for article in articles:
            self.status(f'Removing {article["articleModel"]["simpleSku"]}')

            try:
                delete_art = self.s.delete(
                    url=f'https://{urlparse(self.task_data["TASK_INPUT"]).netloc}/api/cart-gateway/carts/{cart_id}/items/{article["articleModel"]["simpleSku"]}',
                    headers={
                        'authority': urlparse(self.task_data['TASK_INPUT']).netloc,
                        'method': 'DELETE',
                        'path': f'/api/cart-gateway/carts/{cart_id}/items/{article["articleModel"]["simpleSku"]}',
                        'scheme': 'https',
                        'accept': 'application/json',
                        'accept-encoding': 'utf-8',
                        'accept-language': 'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7',
                        'cache-control': 'no-cache',
                        'content-type': 'application/json',
                        'origin': f"https://{urlparse(self.task_data['TASK_INPUT']).netloc}",
                        'referer': f'https://{urlparse(self.task_data["TASK_INPUT"]).netloc}/cart/',
                        'sec-fetch-dest': 'empty',
                        'sec-fetch-mode': 'cors',
                        'sec-fetch-site': 'same-origin',
                        'user-agent': self.s.headers['User-Agent'],
                        'x-xsrf-token': self.s.cookies.get_dict()['frsx']
                    }
                )
            except Exception as e:
                self.error(f'An exception occurred: [{e.__class__.__name__}]')
                self.s.proxies = proxies.get_proxy()
                time.sleep(self.error_delay)
                return self.check_cart()

            #if delete_art.ok == False:
            #    self.error('Delete failed, retrying...')
            #    time.sleep(self.error_delay)
            #    return self.check_cart()

            self.success('Successfully deleted!')

        return self.monitor()

    # ------------------------------------------------------------------------------- #

    def monitor(self):

        while True:

            try:
                r = self.s.get(
                    url=self.task_data['TASK_INPUT'],
                    allow_redirects=False,
                    timeout=15,
                    headers={
                        'authority': urlparse(self.task_data['TASK_INPUT']).netloc,
                        'method': 'GET',
                        'path': self.task_data['TASK_INPUT'].split(urlparse(self.task_data['TASK_INPUT']).netloc)[1],
                        'scheme': 'https',
                        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                        'accept-encoding': 'utf-8',
                        'accept-language': 'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7',
                        'cache-control': 'no-cache',
                        'sec-fetch-dest': 'document',
                        'sec-fetch-mode': 'navigate',
                        'sec-fetch-site': 'same-origin',
                        'sec-fetch-user': '?1',
                        'user-agent': self.s.headers['User-Agent']
                    }
                )
            except Exception as e:
                self.error(f'An exception occurred: [{e.__class__.__name__}]')
                self.s.proxies = proxies.get_proxy()
                time.sleep(self.error_delay)
                continue

            if r.ok == False:
                self.error(f'Request failed: Status Code {r.status_code}')
                self.s.proxies = proxies.get_proxy()
                time.sleep(self.error_delay)
                continue

            soup = bs(markup=r.text, features='lxml')

            try:
                self.title = soup.find(name='h1').text
                self.img = soup.find(name='meta', attrs={'property': 'og:image'})['content']
            except:
                pass

            try:
                self.pids = []

                sizes_json = soup.find(name='script', attrs={'id': 'z-vegas-pdp-props'})
                sizes_json = json.loads(str(sizes_json).split('CDATA')[1].split(']></script>')[0])[0]['model']['articleInfo']['units']

                if self.task_data['MODE'] == 'PRE_CART':
                    for size in sizes_json:
                        size_name = size['size']['local']
                        size_id = size['id']

                        data = {'size': size_name, 'id': size_id}

                        if self.task_data['TASK_SIZE'].upper() == 'RANDOM':
                            self.pids.append(data)
                        else:
                            if str(size_name).strip() == str(self.task_data['TASK_SIZE']).strip():
                                self.pids.append(data)
                            else:
                                continue
                else:
                    for size in sizes_json:
                        if size['stock'] <= 0:
                            continue
                        else:
                            size_name = size['size']['local']
                            size_id = size['id']

                            data = {'size': size_name, 'id': size_id}

                            if self.task_data['TASK_SIZE'].upper() == 'RANDOM':
                                self.pids.append(data)
                            else:
                                if str(size_name).strip() == str(self.task_data['TASK_SIZE']).strip():
                                    self.pids.append(data)
                                else:
                                    continue
            except:
                self.status('Waiting for sizes...')
                self.s.proxies = proxies.get_proxy()
                time.sleep(self.monitor_delay)
                continue

            if self.pids == []:
                self.status('Waiting for restock...')
                self.s.proxies = proxies.get_proxy()
                time.sleep(self.monitor_delay)
                continue

            else:
                self.success(f'Successfully selected {len(self.pids)} size(s)!')
                break

        return self.atc()

    # ------------------------------------------------------------------------------- #

    def atc(self):

        if self.task_data['MODE'] == 'PRE_CART':

            del self.s.cookies['_abck']

            abck_cookie = cookies.get_cookie(self.task_data['TASK_INPUT'])

            self.s.cookies.set(
                name='_abck',
                value=abck_cookie,
                path='/',
                domain=f'.{tldextract.extract(self.task_data["TASK_INPUT"]).domain}.{tldextract.extract(self.task_data["TASK_INPUT"]).suffix}'
            )

            for selected_size in self.pids:
                self.selected = selected_size
                self.status(f'Adding to cart size: {self.selected["size"]}')

                try:
                    r = self.s.post(
                        url=f'https://{urlparse(self.task_data["TASK_INPUT"]).netloc}/api/pdp/cart',
                        allow_redirects=False,
                        timeout=15,
                        json={"simpleSku": self.selected['id'],"anonymous": False},
                        headers={
                            'authority': urlparse(self.task_data['TASK_INPUT']).netloc,
                            'method': 'POST',
                            'path': '/api/pdp/cart',
                            'scheme': 'https',
                            'accept': 'application/json',
                            'accept-encoding': 'utf-8',
                            'accept-language': 'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7',
                            'cache-control': 'no-cache',
                            'content-type': 'application/json',
                            'dpr': '1',
                            'origin': f'https://{urlparse(self.task_data["TASK_INPUT"]).netloc}',
                            'referer': self.task_data['TASK_INPUT'],
                            'sec-fetch-dest': 'empty',
                            'sec-fetch-mode': 'cors',
                            'sec-fetch-site': 'same-origin',
                            'user-agent': self.s.headers['User-Agent'],
                            'viewport-width': '848',
                            'x-xsrf-token': self.s.cookies.get_dict()['frsx']
                        }
                    )
                except Exception as e:
                    self.error(f'An exception occurred: [{e.__class__.__name__}]')
                    self.s.proxies = proxies.get_proxy()
                    time.sleep(self.error_delay)
                    continue

                if r.ok == False and r.status_code != 403:
                    self.error(f'Request failed: Status Code {r.status_code}')
                    self.s.proxies = proxies.get_proxy()
                    time.sleep(self.error_delay)
                    continue

                elif r.status_code == 403:
                    self.error('Akamai IP ban! Retrying...')

                    del self.s.cookies['_abck']

                    abck_cookie = cookies.get_cookie(self.task_data['TASK_INPUT'])

                    self.s.cookies.set(
                        name='_abck',
                        value=abck_cookie,
                        path='/',
                        domain=f'.{tldextract.extract(self.task_data["TASK_INPUT"]).domain}.{tldextract.extract(self.task_data["TASK_INPUT"]).suffix}'
                    )

                    time.sleep(self.error_delay)
                    continue

                try:
                    atc_response = r.json()
                except:
                    self.error('Atc failed, retrying...')
                    time.sleep(self.error_delay)
                    continue

                if atc_response.get('ok') == True:
                    self.success(f'Successfully added to cart size: {self.selected["size"]}')
                else:
                    self.error(f'Size: {self.selected["size"]} is out of stock! Retrying in {self.error_delay} second(s)...')
                    time.sleep(self.error_delay)
                    continue

            return self.address()

        else:
            while self.pids != []:

                self.selected = random.choice(self.pids)
                self.status(f'Adding to cart size: {self.selected["size"]}')

                del self.s.cookies['_abck']

                abck_cookie = cookies.get_cookie(self.task_data['TASK_INPUT'])

                self.s.cookies.set(
                    name='_abck',
                    value=abck_cookie,
                    path='/',
                    domain=f'.{tldextract.extract(self.task_data["TASK_INPUT"]).domain}.{tldextract.extract(self.task_data["TASK_INPUT"]).suffix}'
                )

                try:
                    r = self.s.post(
                        url=f'https://{urlparse(self.task_data["TASK_INPUT"]).netloc}/api/pdp/cart',
                        allow_redirects=False,
                        timeout=15,
                        json={"simpleSku": self.selected['id'],"anonymous": False},
                        headers={
                            'authority': urlparse(self.task_data['TASK_INPUT']).netloc,
                            'method': 'POST',
                            'path': '/api/pdp/cart',
                            'scheme': 'https',
                            'accept': 'application/json',
                            'accept-encoding': 'utf-8',
                            'accept-language': 'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7',
                            'cache-control': 'no-cache',
                            'content-type': 'application/json',
                            'dpr': '1',
                            'origin': f'https://{urlparse(self.task_data["TASK_INPUT"]).netloc}',
                            'referer': self.task_data['TASK_INPUT'],
                            'sec-fetch-dest': 'empty',
                            'sec-fetch-mode': 'cors',
                            'sec-fetch-site': 'same-origin',
                            'user-agent': self.s.headers['User-Agent'],
                            'viewport-width': '848',
                            'x-xsrf-token': self.s.cookies.get_dict()['frsx']
                        }
                    )
                except Exception as e:
                    self.error(f'An exception occurred: [{e.__class__.__name__}]')
                    self.s.proxies = proxies.get_proxy()
                    time.sleep(self.error_delay)
                    continue

                if r.ok == False:
                    self.error(f'Request failed: Status Code {r.status_code}')
                    self.s.proxies = proxies.get_proxy()
                    time.sleep(self.error_delay)
                    continue

                try:
                    atc_response = r.json()
                except:
                    self.error('Atc failed, retrying...')
                    time.sleep(self.error_delay)
                    continue

                if atc_response.get('ok') == True:
                    self.success(f'Successfully added to cart size: {self.selected["size"]}')
                else:
                    self.error(f'Size: {self.selected["size"]} is out of stock! Retrying in {self.error_delay} second(s)...')
                    time.sleep(self.error_delay)
                    continue

                return self.address()

            return self.monitor()

    # ------------------------------------------------------------------------------- #

    def address(self):

        self.status('Submitting address...')

        while True:
            try:
                r = self.s.post(
                    url=f'https://{urlparse(self.task_data["TASK_INPUT"]).netloc}/api/checkout/create-or-update-address',
                    allow_redirects=False,
                    timeout=15,
                    json={
                        "address": {
                            "city": self.task_data['CITY'],
                            "street": f"{self.task_data['STREET_1']} {self.task_data['STREET_2']}",
                            "country_code": self.task_data['COUNTRY_ISO'],
                            "last_name": self.task_data['SURNAME'],
                            "first_name": self.task_data['NAME'],
                            "salutation": "Mr",
                            "zip": self.task_data['ZIPCODE']
                        },
                        "addressDestination": {
                            "destination": {
                                "address": {
                                    "salutation": "Mr",
                                    "first_name": self.task_data['NAME'],
                                    "last_name": self.task_data['SURNAME'],
                                    "country_code": self.task_data['COUNTRY_ISO'],
                                    "city": self.task_data['CITY'],
                                    "zip": self.task_data['ZIPCODE'],
                                    "street": f"{self.task_data['STREET_1']} {self.task_data['STREET_2']}"
                                }
                            },
                            "normalized_address": {
                                "country_code": self.task_data['COUNTRY_ISO'],
                                "city": self.task_data['CITY'],
                                "zip": self.task_data['ZIPCODE'],
                                "street": self.task_data['STREET_1'],
                                "house_number": self.task_data['STREET_2']
                            },
                            "status": "https://docs.riskmgmt.zalan.do/address/correct",
                            "blacklisted": False
                        },
                        "isDefaultShipping": True,
                        "isDefaultBilling": True
                    },
                    headers={
                        'authority': urlparse(self.task_data['TASK_INPUT']).netloc,
                        'method': 'POST',
                        'path': '/api/checkout/create-or-update-address',
                        'scheme': 'https',
                        'accept': 'application/json',
                        'accept-encoding': 'utf-8',
                        'accept-language': 'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7',
                        'cache-control': 'no-cache',
                        'content-type': 'application/json',
                        'origin': f'https://{urlparse(self.task_data["TASK_INPUT"]).netloc}',
                        'referer': f'https://{urlparse(self.task_data["TASK_INPUT"]).netloc}/checkout/address',
                        'sec-fetch-dest': 'empty',
                        'sec-fetch-mode': 'cors',
                        'sec-fetch-site': 'same-origin',
                        'user-agent': self.s.headers['User-Agent'],
                        'x-xsrf-token': self.s.cookies.get_dict()['frsx'],
                        'x-zalando-checkout-app': 'web',
                        'x-zalando-footer-mode': 'desktop',
                        'x-zalando-header-mode': 'desktop'
                    }
                )
            except Exception as e:
                self.error(f'An exception occurred: [{e.__class__.__name__}]')
                self.s.proxies = proxies.get_proxy()
                time.sleep(self.error_delay)
                continue

            if r.ok == False and r.status_code not in [401, 500, 403]:
                self.error(f'Request failed: Status Code {r.status_code}')
                self.s.proxies = proxies.get_proxy()
                time.sleep(self.error_delay)
                continue

            elif r.status_code == 500 and self.task_data['MODE'].upper() != 'PRE_CART':
                self.error(f'Size {self.selected["size"]} is out of stock, retrying...')
                self.pids.remove(self.selected)
                time.sleep(self.error_delay)
                return self.atc()

            elif r.status_code == 401:
                self.error(r.text)
                time.sleep(self.error_delay)
                return self.atc()

            elif r.status_code == 403:
                self.error('Akamai IP Ban! Retrying...')

                del self.s.cookies['_abck']

                abck_cookie = cookies.get_cookie(self.task_data['TASK_INPUT'])

                self.s.cookies.set(
                    name='_abck',
                    value=abck_cookie,
                    path='/',
                    domain=f'.{tldextract.extract(self.task_data["TASK_INPUT"]).domain}.{tldextract.extract(self.task_data["TASK_INPUT"]).suffix}'
                )

                time.sleep(self.error_delay)
                continue

            elif r.status_code == 500 and self.task_data['MODE'].upper() == 'PRE_CART':
                self.status(f'Waiting for "{self.title}" to restock...')
                self.s.proxies = proxies.get_proxy()
                time.sleep(self.monitor_delay)
                continue

            self.success('Successfully submit address!')

            return self.payment_method()

    # ------------------------------------------------------------------------------- #

    def payment_method(self):

        self.status('Submitting payment method...')

        try:
            payment_get = self.s.get(
                url=f"https://{urlparse(self.task_data['TASK_INPUT']).netloc}/api/checkout/update-payment",
                timeout=15,
                headers={
                    'authority': urlparse(self.task_data['TASK_INPUT']).netloc,
                    'method': 'GET',
                    'path': '/api/checkout/update-payment',
                    'scheme': 'https',
                    'accept': '*/*',
                    'accept-encoding': 'utf-8',
                    'accept-language': 'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7',
                    'cache-control': 'no-cache',
                    'referer': f'https://{urlparse(self.task_data["TASK_INPUT"]).netloc}/checkout/confirm',
                    'sec-fetch-dest': 'empty',
                    'sec-fetch-mode': 'cors',
                    'sec-fetch-site': 'same-origin',
                    'user-agent': self.s.headers['User-Agent'],
                    'x-xsrf-token': self.s.cookies.get_dict()['frsx'],
                    'x-zalando-checkout-app': 'web',
                    'x-zalando-footer-mode': 'desktop',
                    'x-zalando-header-mode': 'desktop'
                }
            )

            payment_url = str(payment_get.json()['url'])

            payment_get_2 = self.s.get(
                url=payment_url,
                timeout=15,
                headers={
                    'authority': 'checkout.payment.zalando.com',
                    'method': 'GET',
                    'path': payment_url.split('checkout.payment.zalando.com')[1],
                    'scheme': 'https',
                    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                    'accept-encoding': 'utf-8',
                    'accept-language': 'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7',
                    'cache-control': 'no-cache',
                    'referer': f'https://{urlparse(self.task_data["TASK_INPUT"]).netloc}/checkout/confirm',
                    'sec-fetch-dest': 'document',
                    'sec-fetch-mode': 'navigate',
                    'sec-fetch-site': 'cross-site',
                    'sec-fetch-user': '?1',
                    'user-agent': self.s.headers['User-Agent'],
                }
            )

            payment_post_1 = self.s.post(
                url=payment_url,
                timeout=15,
                allow_redirects=False,
                headers={
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                    'Accept-Encoding': 'utf-8',
                    'Accept-Language': 'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7',
                    'Cache-Control': 'no-cache',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Host': 'checkout.payment.zalando.com',
                    'Origin': 'https://checkout.payment.zalando.com',
                    'Referer': 'https://checkout.payment.zalando.com/selection?show=true',
                    'Sec-Fetch-Dest': 'document',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-Site': 'same-origin',
                    'Sec-Fetch-User': '?1',
                    'User-Agent': self.s.headers['User-Agent'],
                },
                data={
                    'payz_credit_card_former_payment_method_id': '-1',
                    'payz_selected_payment_method': self.task_data['TASK_PAYMENT_METHOD'],
                    'iframe_funding_source_id': ''
                }
            )

            payment_post_2 = self.s.post(
                url='https://checkout.payment.zalando.com/selection',
                timeout=15,
                allow_redirects=False,
                headers={
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                    'Accept-Encoding': 'utf-8',
                    'Accept-Language': 'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7',
                    'Cache-Control': 'no-cache',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Host': 'checkout.payment.zalando.com',
                    'Origin': 'https://checkout.payment.zalando.com',
                    'Referer': 'https://checkout.payment.zalando.com/selection?show=true',
                    'Sec-Fetch-Dest': 'document',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-Site': 'same-origin',
                    'Sec-Fetch-User': '?1',
                    'User-Agent': self.s.headers['User-Agent'],
                },
                data={
                    'payz_credit_card_former_payment_method_id': '-1',
                    'payz_selected_payment_method': self.task_data['TASK_PAYMENT_METHOD'],
                    'iframe_funding_source_id': ''
                }
            )
        except Exception as e:
            self.error(f'An exception occurred: [{e.__class__.__name__}]')
            self.s.proxies = proxies.get_proxy()
            time.sleep(self.error_delay)
            return self.payment_method()

        if payment_post_2.ok == False:
            self.error(f'Request failed: Status Code {payment_post_2.status_code}')
            self.s.proxies = proxies.get_proxy()
            time.sleep(self.error_delay)
            return self.payment_method()

        self.success('Successfully submit payment method!')

        return self.confirm()

    # ------------------------------------------------------------------------------- #

    def confirm(self):

        if self.task_data['MODE'].upper() == 'PRE_CART':
            while True:

                self.status('Confirming payment...')

                try:
                    r = self.s.get(
                        url=f'https://{urlparse(self.task_data["TASK_INPUT"]).netloc}/checkout/payment-complete',
                        timeout=15,
                        allow_redirects=True,
                        headers={
                            'authority': urlparse(self.task_data['TASK_INPUT']).netloc,
                            'method': 'GET',
                            'path': '/checkout/payment-complete',
                            'scheme': 'https',
                            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                            'accept-encoding': 'utf-8',
                            'accept-language': 'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7',
                            'cache-control': 'no-cache',
                            'referer': 'https://checkout.payment.zalando.com/selection?show=true',
                            'sec-fetch-dest': 'document',
                            'sec-fetch-mode': 'navigate',
                            'sec-fetch-site': 'cross-site',
                            'sec-fetch-user': '?1',
                            'user-agent': self.s.headers['User-Agent'],
                        }
                    )
                except Exception as e:
                    self.error(f'An exception occurred: [{e.__class__.__name__}]')
                    self.s.proxies = proxies.get_proxy()
                    time.sleep(self.error_delay)
                    continue

                if r.ok == False and r.status_code not in [403]:
                    self.error(f'Request failed: Status Code {r.status_code}')
                    self.s.proxies = proxies.get_proxy()
                    time.sleep(self.error_delay)
                    continue

                elif r.status_code == 403:
                    self.error('Akamai IP Ban! Retrying...')

                    del self.s.cookies['_abck']

                    abck_cookie = cookies.get_cookie(self.task_data['TASK_INPUT'])

                    self.s.cookies.set(
                        name='_abck',
                        value=abck_cookie,
                        path='/',
                        domain=f'.{tldextract.extract(self.task_data["TASK_INPUT"]).domain}.{tldextract.extract(self.task_data["TASK_INPUT"]).suffix}'
                    )

                    time.sleep(self.error_delay)
                    continue

                soup = bs(markup=r.text, features='lxml')

                self.checkout_data = None

                for e in soup.find_all(name='div'):
                    div_soup = bs(markup=str(e), features='lxml')

                    try:
                        self.checkout_data = div_soup.find(name='div')['data-props']
                        break
                    except:
                        continue

                if self.checkout_data:
                    try:
                        self.checkout_data = json.loads(self.checkout_data)
                    except:
                        self.status(f'Waiting for "{self.title}" to restock...')
                        self.s.proxies = proxies.get_proxy()
                        time.sleep(self.error_delay)
                        continue
                else:
                    self.status(f'Waiting for "{self.title}" to restock...')
                    self.s.proxies = proxies.get_proxy()
                    time.sleep(self.error_delay)
                    continue

                self.status('Processing...')

                try:
                    payment = self.s.post(
                        url=f'https://{urlparse(self.task_data["TASK_INPUT"]).netloc}/api/checkout/buy-now',
                        timeout=15,
                        allow_redirects=False,
                        headers={
                            'authority': urlparse(self.task_data['TASK_INPUT']).netloc,
                            'method': 'POST',
                            'path': '/api/checkout/buy-now',
                            'scheme': 'https',
                            'accept': 'application/json',
                            'accept-encoding': 'utf-8',
                            'accept-language': 'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7',
                            'cache-control': 'no-cache',
                            'content-type': 'application/json',
                            'origin': f'https://{urlparse(self.task_data["TASK_INPUT"]).netloc}',
                            'referer': f'https://{urlparse(self.task_data["TASK_INPUT"]).netloc}/checkout/confirm',
                            'sec-fetch-dest': 'empty',
                            'sec-fetch-mode': 'cors',
                            'sec-fetch-site': 'same-origin',
                            'user-agent': self.s.headers['User-Agent'],
                            'x-xsrf-token': self.s.cookies.get_dict()['frsx'],
                            'x-zalando-checkout-app': 'web',
                            'x-zalando-footer-mode': 'desktop',
                            'x-zalando-header-mode': 'desktop'
                        },
                        json={
                            "checkoutId": self.checkout_data['model']['checkoutId'],
                            "eTag": self.checkout_data['model']['eTag']
                        }
                    )
                except Exception as e:
                    self.error(f'An exception occurred: [{e.__class__.__name__}]')
                    self.s.proxies = proxies.get_proxy()
                    time.sleep(self.error_delay)
                    continue

                if payment.ok == False and payment.status_code not in [403]:
                    self.error(f'Request failed: Status Code {payment.status_code}')
                    self.s.proxies = proxies.get_proxy()
                    time.sleep(self.error_delay)
                    continue

                elif payment.status_code == 403:
                    self.error('Akamai IP Ban! Retrying...')

                    del self.s.cookies['_abck']

                    abck_cookie = cookies.get_cookie(self.task_data['TASK_INPUT'])

                    self.s.cookies.set(
                        name='_abck',
                        value=abck_cookie,
                        path='/',
                        domain=f'.{tldextract.extract(self.task_data["TASK_INPUT"]).domain}.{tldextract.extract(self.task_data["TASK_INPUT"]).suffix}'
                    )

                    time.sleep(self.error_delay)
                    continue

                try:
                    payment_url = payment.json()['url']
                except:
                    self.error('Checkout failed: impossible to parse response!')
                    time.sleep(self.error_delay)
                    continue

                if self.task_data['TASK_PAYMENT_METHOD'] == 'CASH_ON_DELIVERY':
                    if 'success' in str(payment_url):
                        self.success('Successful Checkout!')
                        self.send_webhook()
                        self.s.cookies.clear()
                        return self.login()
                    else:
                        self.status(f'Waiting for "{self.title}" to restock...')
                        self.s.proxies = proxies.get_proxy()
                        time.sleep(self.error_delay)
                        continue
                else:
                    if '&token' in str(payment_url):
                        self.success('Successful Checkout!')
                        self.checkouts += 1
                        self.send_webhook()
                        self.s.cookies.clear()
                        return self.login()
                    else:
                        self.status(f'Waiting for "{self.title}" to restock...')
                        self.s.proxies = proxies.get_proxy()
                        time.sleep(self.error_delay)
                        continue

        else:
            while True:

                self.status('Confirming payment...')

                try:
                    r = self.s.get(
                        url=f'https://{urlparse(self.task_data["TASK_INPUT"]).netloc}/checkout/payment-complete',
                        timeout=15,
                        allow_redirects=True,
                        headers={
                            'authority': urlparse(self.task_data['TASK_INPUT']).netloc,
                            'method': 'GET',
                            'path': '/checkout/payment-complete',
                            'scheme': 'https',
                            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                            'accept-encoding': 'utf-8',
                            'accept-language': 'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7',
                            'cache-control': 'no-cache',
                            'referer': 'https://checkout.payment.zalando.com/selection?show=true',
                            'sec-fetch-dest': 'document',
                            'sec-fetch-mode': 'navigate',
                            'sec-fetch-site': 'cross-site',
                            'sec-fetch-user': '?1',
                            'user-agent': self.s.headers['User-Agent'],
                        }
                    )
                except Exception as e:
                    self.error(f'An exception occurred: [{e.__class__.__name__}]')
                    self.s.proxies = proxies.get_proxy()
                    time.sleep(self.error_delay)
                    continue

                if r.ok == False and r.status_code not in [403]:
                    self.error(f'Request failed: Status Code {r.status_code}')
                    self.s.proxies = proxies.get_proxy()
                    time.sleep(self.error_delay)
                    continue

                elif r.status_code == 403:
                    self.error('Akamai IP Ban! Retrying...')

                    del self.s.cookies['_abck']

                    abck_cookie = cookies.get_cookie(self.task_data['TASK_INPUT'])

                    self.s.cookies.set(
                        name='_abck',
                        value=abck_cookie,
                        path='/',
                        domain=f'.{tldextract.extract(self.task_data["TASK_INPUT"]).domain}.{tldextract.extract(self.task_data["TASK_INPUT"]).suffix}'
                    )

                    time.sleep(self.error_delay)
                    continue

                soup = bs(markup=r.text, features='lxml')

                self.checkout_data = None

                for e in soup.find_all(name='div'):
                    div_soup = bs(markup=str(e), features='lxml')

                    try:
                        self.checkout_data = div_soup.find(name='div')['data-props']
                        break
                    except:
                        continue

                if self.checkout_data:
                    try:
                        self.checkout_data = json.loads(self.checkout_data)
                    except:
                        self.error('Checkout failed!')
                        time.sleep(self.error_delay)
                        return self.monitor()
                else:
                    self.error('Checkout failed!')
                    time.sleep(self.error_delay)
                    return self.monitor()

                self.status('Processing...')

                try:
                    payment = self.s.post(
                        url=f'https://{urlparse(self.task_data["TASK_INPUT"]).netloc}/api/checkout/buy-now',
                        timeout=15,
                        allow_redirects=False,
                        headers={
                            'authority': urlparse(self.task_data['TASK_INPUT']).netloc,
                            'method': 'POST',
                            'path': '/api/checkout/buy-now',
                            'scheme': 'https',
                            'accept': 'application/json',
                            'accept-encoding': 'utf-8',
                            'accept-language': 'it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7',
                            'cache-control': 'no-cache',
                            'content-type': 'application/json',
                            'origin': f'https://{urlparse(self.task_data["TASK_INPUT"]).netloc}',
                            'referer': f'https://{urlparse(self.task_data["TASK_INPUT"]).netloc}/checkout/confirm',
                            'sec-fetch-dest': 'empty',
                            'sec-fetch-mode': 'cors',
                            'sec-fetch-site': 'same-origin',
                            'user-agent': self.s.headers['User-Agent'],
                            'x-xsrf-token': self.s.cookies.get_dict()['frsx'],
                            'x-zalando-checkout-app': 'web',
                            'x-zalando-footer-mode': 'desktop',
                            'x-zalando-header-mode': 'desktop'
                        },
                        json={
                            "checkoutId": self.checkout_data['model']['checkoutId'],
                            "eTag": self.checkout_data['model']['eTag']
                        }
                    )
                except Exception as e:
                    self.error(f'An exception occurred: [{e.__class__.__name__}]')
                    self.s.proxies = proxies.get_proxy()
                    time.sleep(self.error_delay)
                    continue

                if payment.ok == False and payment.status_code not in [403]:
                    self.error(f'Request failed: Status Code {payment.status_code}')
                    self.s.proxies = proxies.get_proxy()
                    time.sleep(self.error_delay)
                    continue

                elif payment.status_code == 403:
                    self.error('Akamai IP Ban! Retrying...')

                    del self.s.cookies['_abck']

                    abck_cookie = cookies.get_cookie(self.task_data['TASK_INPUT'])

                    self.s.cookies.set(
                        name='_abck',
                        value=abck_cookie,
                        path='/',
                        domain=f'.{tldextract.extract(self.task_data["TASK_INPUT"]).domain}.{tldextract.extract(self.task_data["TASK_INPUT"]).suffix}'
                    )

                    time.sleep(self.error_delay)
                    continue

                try:
                    payment_url = payment.json()['url']
                except:
                    self.error('Checkout failed: impossible to parse response!')
                    time.sleep(self.error_delay)
                    continue

                if self.task_data['TASK_PAYMENT_METHOD'] == 'CASH_ON_DELIVERY':
                    if 'success' in str(payment_url):
                        self.success('Successful Checkout!')
                        self.send_webhook()
                        self.s.cookies.clear()
                        return self.login()
                    else:
                        self.error('Checkout failed!')
                        time.sleep(self.error_delay)
                        return self.monitor()
                else:
                    if '&token' in str(payment_url):
                        self.success('Successful Checkout!')
                        self.checkouts += 1
                        self.send_webhook()
                        self.s.cookies.clear()
                        return self.login()
                    else:
                        self.error('Checkout failed!')
                        time.sleep(self.error_delay)
                        return self.monitor()

# ------------------------------------------------------------------------------- #
