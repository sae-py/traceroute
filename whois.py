from ipwhois import IPWhois

who = IPWhois('24.24.24.24').lookup()
nets = who['nets']
country = nets[0]['country']
company = nets[0]['description']

print("国：{0}\n持ち主：{1}".format(country,company))
