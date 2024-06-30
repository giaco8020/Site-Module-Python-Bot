# ------------------------------------------------------------------------------- #

import cloudscraper, json, time, config, random, tldextract, uuid, datetime, threading
from bs4 import BeautifulSoup
from urllib.parse import urlparse, unquote
from bot.logs import console
from bot.akamai import cookies
from bot import read_settings, close
from discord_webhook import DiscordWebhook, DiscordEmbed
from faker import Faker
import urllib.request
import contextlib
from urllib.parse import urlencode
from urllib.request import urlopen
import base64
from selenium import webdriver
from bot.proxies import proxies
from dhooks import Webhook, Embed

# ------------------------------------------------------------------------------- #
class Lv_monitor:

    # ------------------------------------------------------------------------------- #

    def __init__(self, session: cloudscraper.CloudScraper, **kwargs):

        self.store = 'Lv_monitor'

        self.headers = {
            "authority": "it.louisvuitton.com",
            "method": "GET",
            "scheme": "https",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
            "accept-encoding": "gzip, deflate, br",
            "accept-language": "it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7,de;q=0.6,es;q=0.5",
            "cache-control": "max-age=0",
            "sec-fetch-dest": "document",
            "sec-fetch-mode": "navigate",
            "sec-fetch-site": "none",
            "sec-fetch-user": "?1",
            "upgrade-insecure-requests": "1",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36"
            }

        self.task_data = kwargs.get('task_data', None)

        self.settings_json = read_settings.read()

        self.discord_webhook = self.settings_json['DISCORD_WEBHOOK']
        self.monitor_delay = self.settings_json['MONITOR_DELAY']



        try:
            self.monitor_delay = int(self.monitor_delay)
        except:
            self.error('Delays must be integers. Check your settings.csv file.')
            close.execute()


        self.pids = []
        self.selected = {}
        self.img = None

        self.s = session
        self.s.trust_env = False
        self.s.verify = True


        self.monitor_frontend()


    # ------------------------------------------------------------------------------- #


    # ------------------------------------------------------------------------------- #

    def send_webhook_monitor_frontend(self):

        try:

            hook = Webhook(url=self.discord_webhook)
            embed = Embed(color=7185217, timestamp=True, description=None)
            embed.set_title(title=self.name, url=self.task_data["TASK_INPUT"])
            embed.add_field(name='Website',
                            value="LouisVuitton",
                            inline=False)
            embed.add_field(name='Sizes', value="One size")
            embed.set_footer(text='')

        except Exception as e:
            print(e)

        try:
            hook.send(embeds=embed)
        except:
            pass

    def send_webhook_monitor_backend(self):

        try:
            webhook = DiscordWebhook(url=self.discord_webhook)
            embed = DiscordEmbed(color=255690, timestamp=True, description=None)
            embed.set_author(name=str(self.task_data["NAME"]), url="https://it.louisvuitton.com/ita-it/ricerca/"+str(self.task_data["TASK_INPUT"]))
            # set thumbnail
            embed.set_thumbnail(url='https://it.louisvuitton.com/ita-it/ricerca/'+str(self.task_data["TASK_INPUT"]))
            # set footer
            embed.set_footer(text='')
            # set timestamp (default is now)
            embed.set_timestamp()

            webhook.add_embed(embed)
            webhook.execute()

        except Exception as e:
            print(e)


    # ------------------------------------------------------------------------------- #

    def status(self, msg: str):

        console.status(f'[{self.store}-{self.task_data["TASK_ID"]}] {msg}')

    # ------------------------------------------------------------------------------- #

    def error(self, msg: str):

        console.error(f'[{self.store}-{self.task_data["TASK_ID"]}] {msg}')

    # ------------------------------------------------------------------------------- #

    def success(self, msg: str):

        console.success(f'[{self.store}-{self.task_data["TASK_ID"]}] {msg}')

    # ------------------------------------------------------------------------------- #

    def monitor_frontend(self):

        self.s.proxies = proxies.get_proxy()

        while True:

            try:

                self.s.cookies.clear()


                self.name = str(self.task_data["NAME"])
                self.pid_monitor = str(self.task_data["TASK_INPUT"])
                self.size = str(self.task_data["SURNAME"])


                # ---------------------VEDO SE IN STOCK-----------------------------


                link_stock = "https://it.louisvuitton.com/ajaxsecure/getStockLevel.jsp?storeLang=ita-it&pageType=storelocator_section&skuIdList=" + self.pid_monitor

                try:
                    self.monitor_stock_requests = self.s.get(link_stock, headers=self.headers)

                except:
                    console.error("Proxy Error")
                    time.sleep(1)
                    self.monitor_frontend()


                #print(self.monitor_stock_requests.content)
                #print(self.monitor_stock_requests.status_code)

                if (self.monitor_stock_requests.status_code == 200):
                    pass
                else:
                    console.error("Connection error!")
                    time.sleep(self.monitor_delay)
                    self.monitor_frontend()

                json_stock = json.loads(self.monitor_stock_requests.content)

                print(json_stock)


                if (json_stock[self.pid_monitor]["inStock"] == True):
                    console.success("Size in stock -->" + self.pid_monitor)
                    self.send_webhook_monitor_frontend()

                    while True:

                        try:

                            self.monitor_sold_item = self.s.get(link_stock, headers=self.headers)

                            if (self.monitor_sold_item.status_code == 200):
                                pass
                            else:
                                console.error("Connection error!")
                                time.sleep(self.monitor_delay)
                                self.monitor_frontend()

                            json_stock_2 = json.loads(self.monitor_sold_item.content)

                            if (json_stock_2[self.pid_monitor]["inStock"] == True):
                                console.success(str(self.name) + "[" + str(self.pid_monitor) + "] --> IN STOCK")
                                time.sleep(self.monitor_delay)
                                del self.monitor_sold_item, json_stock_2

                            else:
                                console.status(str(self.name) + "[" + str(self.pid_monitor) + "] --> OOS")
                                del  self.pid_monitor, self.name, link_stock, self.monitor_stock_requests, json_stock
                                time.sleep(1)
                                self.monitor_frontend()


                        except Exception as e:
                            console.error(e)
                            self.monitor_frontend()

                else:
                    console.status(str(self.name) + "[" + str(self.pid_monitor) + "] --> OOS")
                    del self.pid_monitor, self.name, link_stock, self.monitor_stock_requests, json_stock
                    time.sleep(1)

            except Exception as e:
                console.error(e)
                self.monitor_backend()








