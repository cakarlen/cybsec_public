import re
import time
import bs4
import requests
from time import sleep


'''
get private virus total api key
check out ibm x api 


IBM X-Force API Stuff:
Key: 618259d2-285b-43d5-8e49-0dd2f04c3d59
Pass: d52140b7-780c-4627-b14e-81d014c3e23c
5,000 records per month limit but its freeeeee


'''


class Lookup:
    def __init__(self, ip, resolved_ip, user_input):
        self.ip = ip
        self.resolved_ip = resolved_ip
        self.user_input = user_input

    def talos(self):
        location = {}
        results = [
            {
                "talos": {
                    "location": [],
                    "blacklist": [],
                    "information": []
                }
            }
        ]

        if self.ip == "":
            self.ip = self.resolved_ip
        else:
            self.ip = self.ip

        headers = {
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'en-US,en;q=0.9',
            'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_0) AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/75.0.3770.90 Safari/537.36',
            'accept': 'application/json, text/javascript, */*; q=0.01',
            'referer': f'https://www.talosintelligence.com/reputation_center/lookup?search={self.ip}',
            'authority': 'www.talosintelligence.com',
            'cookie': '__cfduid=d3cc53ad77e3e73f44f90184a51c9a21b1557752732; cf_clearance=ec456d5a0aedb15ef1b2c5c4'
                      'df0f408d3f9d1823-1561044127-86400-250; _talos_website_session=RmVIRGFldDR1NVFrc2MwcmJ1N0pZW'
                      'E13L2NhamkvaEQzU1d0WEdUYld5VkQ1dEpKR3VPYU1jSHdNcGZydWtIdk40NkJ1MmVGbDFoVHZTRUh6bHNqNy8vSE5q'
                      'VGpzcGdGZkMrOUF6SjhTSCsrV3BFek1OU201dngwRzRDaXBnOG5xOVYrK3BWOVFqb1hWZXVZY3dadEZTUlhJQTBKc1N'
                      'UVE8yN1p3a2VHWDU0bDFydTExT2xNNy91b2FLVVRhOU02WkhPb3BTclNSQTAxMllLL3lsM1U5V1Z2YzZ3S3lORUtFNH'
                      'daTGsxNllSYz0tLTRKYUxsZ01jMzZoL3hvUDdHejBJMVE9PQ%3D%3D--9b5b02c6b242aa53dcc4c61a2443974557f'
                      '98d79',
        }

        params = (
            ('query', '/api/v2/location/ip/'),
            ('query_entry', self.ip),
            ('offset', '0'),
            ('order', 'ip asc'),
        )

        get_loc = requests.get('https://www.talosintelligence.com/sb_api/query_lookup',
                               headers=headers, params=params).json()

        del get_loc['map']
        del get_loc['locations']
        del get_loc['country_code']
        del get_loc['country_flag']

        for key, value in get_loc.items():
            location = get_loc[key]

        does_exist = False
        for i in location:
            del i['country_code']
            del i['country_flag']
            i['Country'] = i.pop("country")
            i['City'] = i.pop("name")

        for second_value in location:
            for i, j in second_value.items():
                if i != "" and j != "":
                    results[0]["talos"]["location"].append('{}: {}'.format(i, j))
                    does_exist = True
                else:
                    does_exist = False

        if not does_exist:
            results[0]["talos"]["location"].append("No location data available")

        # -----------------------------------------------------------

        headers = {
            'accept-encoding': 'gzip, deflate, br',
            'accept-language': 'en-US,en;q=0.9',
            'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_0) AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/75.0.3770.90 Safari/537.36',
            'accept': 'application/json, text/javascript, */*; q=0.01',
            'referer': f'https://www.talosintelligence.com/reputation_center/lookup?search={self.ip}',
            'authority': 'www.talosintelligence.com',
            'cookie': '__cfduid=d3cc53ad77e3e73f44f90184a51c9a21b1557752732; cf_clearance=ec456d5a0aedb15ef1b2c5c4df'
                      '0f408d3f9d1823-1561044127-86400-250; _talos_website_session=enV3K1F6R1dESG4renRldktmNU1KczBza'
                      'GR1SWVRaXBKNVhmWGdPa3o4TURKdGNteG9mcERMR1pRWTZPRVlKaFJxeWcxbHVDRGFKRldHWW1QcWxtdnVXY0FWSEZjZm'
                      'NQM3lnMXJ5ZFpWQ0VxR1dhKzdVTzIwSFVQMHBZRTVIaXZZcGJxSVNsN0J3enVoUkJVK1lJVUpwTXAwVi9LM1c1OUorK2R'
                      '6WWVrRlFjT2s3WGlLSUg2MEd3b1JYYWdrWEExcVVYdzdHa1lnaGxtU3JvSGZ0L01va3BYVTJPNUdLMEYyaG5Hdm14am5H'
                      'TT0tLXF2T0krRUpZZFJ4U1dMREVzdE5Rd3c9PQ%3D%3D--e174c533ab502549e6e3d0d661de8ac2f9d2a864',
        }

        params = (
            ('query', '/api/v2/details/ip/'),
            ('query_entry', self.ip),
            ('offset', '0'),
            ('order', 'ip asc'),
        )

        get_query = requests.get('https://www.talosintelligence.com/sb_api/query_lookup',
                                 headers=headers, params=params).json()

        if get_query["dnsmatch"] == 1:
            get_query["dnsmatch"] = "Yes"
        else:
            get_query["dnsmatch"] = "No"

        blacklist = get_query["blacklists"]

        del get_query["display_ipv6_volume"]
        del get_query["cidr"]
        del get_query["daychange"]
        del get_query["blacklists"]
        del get_query["daily_spam_level"]
        del get_query["monthly_spam_level"]

        get_query["IP"] = get_query.pop("ip")
        get_query["Reverse DNS match"] = get_query.pop("dnsmatch")
        get_query["Organization"] = get_query.pop("organization")
        get_query["Email reputation"] = get_query.pop("email_score_name")
        get_query["Web reputation"] = get_query.pop("web_score_name")
        get_query["Daily spam severity"] = get_query.pop("daily_spam_name")
        get_query["Daily spam volume"] = get_query.pop("daily_mag")
        get_query["Monthly spam severity"] = get_query.pop("monthly_spam_name")
        get_query["Monthly spam volume"] = get_query.pop("monthly_mag")

        remove_dup = []

        for black, get_black in blacklist.items():
            for rules, second_get_black in get_black.items():
                new_black = "Not Found" if not second_get_black else second_get_black
                if black not in remove_dup:
                    if type(new_black) != str:
                        if "Not Found" not in new_black:
                            for _ in new_black:
                                results[0]["talos"]["blacklist"].append(black + ": Yes")
                    else:
                        results[0]["talos"]["blacklist"].append(black + ": No")

                remove_dup.append(black)

        edited_query = {x: y for x, y in get_query.items() if y}

        for key, value in edited_query.items():
            results[0]["talos"]["information"].append(str(key) + ": " + str(value))

        return results

    def abuseipdb(self):
        does_exist = False
        results = [
            {
                "abuseipdb": {
                    "summary": [],
                    "information": []
                }
            }
        ]

        get_abuseipad = requests.get(f"https://www.abuseipdb.com/check/{self.ip}")
        get_html = bs4.BeautifulSoup(get_abuseipad.text, "html.parser")

        try:
            get_desc = get_html.select_one('#report-wrapper > p:nth-child(3)').get_text()

            get_confidence = get_html.select_one('#report-wrapper > div:nth-child(1) > div:nth-child(1) '
                                                 '> div > p:nth-child(2)').get_text()
            results[0]["abuseipdb"]["summary"].append(get_desc)
            results[0]["abuseipdb"]["summary"].append(get_confidence)
            does_exist = True
        except AttributeError:
            results[0]["abuseipdb"]["summary"].append("IP address not listed in AbuseIPDB")

        if does_exist:
            all_comments = get_html.find_all('td', attrs={'data-title': 'Comment'})
            new_comments = []

            for i in all_comments:
                new_comments.append(re.sub(r'\n\s*\n', '\n', i.text.strip()))

            get_comments = list(filter(None, new_comments))

            for comment in get_comments:
                results[0]["abuseipdb"]["information"].append(comment)

        return results

    def virustotal_run(self):
        my_api = "73d5b7f5cf3b78014063839a1f0700ef5d82d8d0b6a56b33b3b662ca3455a824"
        results = [
            {
                "virustotal": {
                    "summary": [],
                    "resolutions": [],
                    "domain": [],
                    "url": []
                }
            }
        ]

        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        params = {'apikey': my_api, 'ip': self.ip}
        report = requests.get(url, params=params)
        sleep(5)

        if report.status_code == 200:
            result = report.json()
        elif report.status_code == 204:
            results[0]["virustotal"]["summary"].append(
                "Please wait a minute for VirusTotal API check window to reopen!")
        else:
            results[0]["virustotal"]["summary"].append(f"HTML Status Code: {report.status_code}")

    

        for key, value in result.items():
            if "verbose_msg" in key:
                if "Missing IP address" in value:
                    results[0]["virustotal"]["summary"].append("IP/URL does not exist in Virustotal")

        detected_url = []

        if "resolutions" in result.keys():
            if result['resolutions']:
                for items in result['resolutions']:
                    if items['hostname']:
                        if len(items['hostname']) > 10:
                            results[0]["virustotal"]["resolutions"].append(items['hostname'])
                        else:
                            results[0]["virustotal"]["resolutions"].append(items['hostname'])
                        detected_url.append(items['hostname'])
                    # else:
                    #     print("No URLs associated")
            else:
                results[0]["virustotal"]["resolutions"].append("No resolved URLs associated with IP")
        else:
            results[0]["virustotal"]["resolutions"].append("No resolved URLs associated with IP")


        if result['response_code'] is not 0:
            if "detected_urls" in result.keys():
                if result['detected_urls']:

                    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
                    params = {'apikey': my_api, 'domain': self.user_input}
                    domain_report = requests.get(url, params=params)

                    sleep(3)

                    domain_status = True
                    while domain_status:
                        if domain_report.status_code != 200:
                            time.sleep(30)
                            domain_report = requests.get(url, params=params)
                        else:
                            domain_status = False

                    domain_result = domain_report.json()

                    if "detected_urls" in domain_result.keys():
                        if domain_result['detected_urls'] is not None:
                            results[0]["virustotal"]["domain"].append("URL: " + self.user_input)
                            if "BitDefender category" in domain_result:
                                results[0]["virustotal"]["domain"].append(
                                    "BitDefender category: " + domain_result['BitDefender category'])
                            if "Forcepoint ThreatSeeker category" in domain_result:
                                results[0]["virustotal"]["domain"].append("Forcepoint ThreatSeeker category: " +
                                                                          domain_result[
                                                                              'Forcepoint ThreatSeeker category'])
                        else:
                            if "BitDefender category" in domain_result:
                                results[0]["virustotal"]["domain"].append("URL: " + self.user_input + "\n"
                                                                          + "BitDefender category: "
                                                                          + domain_result['BitDefender category'] +
                                                                          "\n" + "Detected URL: " + domain_result[
                                                                              'detected_urls'])
                            if "Forcepoint ThreatSeeker category" in domain_result:
                                results[0]["virustotal"]["domain"].append("URL: " + self.user_input + "\n"
                                                                          + "Forcepoint ThreatSeeker category: "
                                                                          + domain_result
                                                                          ['Forcepoint ThreatSeeker category'] +
                                                                          "\n" + "Detected URL: " + domain_result[
                                                                              'detected_urls'])
                            else:
                                results[0]["virustotal"]["domain"].append("URL: " + self.user_input + "\n"
                                                                          + "Forcepoint ThreatSeeker category: "
                                                                          + domain_result
                                                                          ['Forcepoint ThreatSeeker category'] +
                                                                          "\n" + "Detected URL: " + domain_result[
                                                                              'detected_urls'])
                    else:
                        results[0]["virustotal"]["domain"].append("No category for URL")


        url = 'https://www.virustotal.com/vtapi/v2/url/report'
        # change user_input to passed in name
        params = {'apikey': my_api, 'resource': self.user_input}
        # params = {'apikey': my_api, 'resource': original_input}
        url_report = requests.get(url, params=params)

        sleep(3)

        url_status = True
        while url_status:
            if url_report.status_code != 200:
                time.sleep(30)
                url_report = requests.get(url, params=params)
            else:
                url_status = False

        url_result = url_report.json()

        # if ip_result['detected_urls']:
        try:
            results[0]["virustotal"]["url"].append(self.user_input + " - " +
                                                   str(url_result['positives']) + "/" + str(url_result['total']))
        except KeyError:
            pass
        try:
            for scan, value in url_result.items():
                if "scans" in scan:
                    for sec_scan, sec_value in value.items():
                        new_value = "Detected" if sec_value['detected'] else "Undetected"
                        if "Detected" in new_value:
                            results[0]["virustotal"]["url"].append(sec_scan + ": " + new_value + ": "
                                                                   + sec_value['result'])
        except AttributeError:
            results[0]["virustotal"]["url"].append("Unable to retrieve URL details")

        return results
