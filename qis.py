#!/usr/bin/env python
# -*- coding: utf-8 -*-
import httplib, urllib, re, sys, datetime, logging, traceback, getpass, math
from StringIO import *
from gzip import *

try:
	import BeautifulSoup
	HAVE_BeautifulSoup = True
except Exception, e:
	HAVE_BeautifulSoup = False

# logging
logFormat = '%(asctime)s %(name)-9s %(levelname)-8s: %(message)s'
logDatefmt = "%H:%M:%S"
logLevel = logging.DEBUG
logging.basicConfig(level=logLevel, format=logFormat, datefmt=logDatefmt)

#: logging object
log = logging.getLogger("qis")

def parseGrades(rContent):
	grades = list()
	names = "EDV_Nr Studiengang Name Art Semester Note Status ECTS SWS Vermerk Versuch Datum".split()
	integerValues = [names[0], names[7], names[8], names[10]]
	floatValues = [names[5]]

	tableCrit = {"cellspacing" : "0", "width" : "100%", "cellpadding" : "5", "border" : "1", "align" : "center"}

	if not HAVE_BeautifulSoup:
		log.error("No Beautiful Soup, no HTML parsing.")
		log.error("Visit 'http://www.crummy.com/software/BeautifulSoup/' or use 'easy_install BeautifulSoup' to install this module.")
		return grades

	start = datetime.datetime.now()

	soup = BeautifulSoup.BeautifulSoup(rContent)
	rows = soup.find("table", tableCrit).findAll("tr")

	for items in [row.findAll("td") for row in rows]:
		if len(items) == 12:
			d = dict()
			for (name, value) in zip(names, map( lambda x: x.text.replace("&nbsp;", ''), items)):
				if value == '':
					value = None
				else:
					if name in integerValues:
						try:
							value = int(value)
						except Exception, e:
							value = 0
					elif name in floatValues:
						try:
							value = float(value.replace(",", "."))
						except Exception, e:
							value = 0.0
				d[name] = value
			grades.append(d)
	duration = datetime.datetime.now() - start
	log.debug("Parsing time: %s" % duration)
	return grades

def sortGrades(a, b):
	"""
	Sortierung der belegten Kurse: Kurse ohne Noten ans Ende.
	"""
	if b['Note'] == None:
		return -1
	elif (a['Note'] == None):
		return 1
	return 0

def formatGrades(grades):
	"""
	Aufbereitung der Noten und Kurse
	"""
	if len(grades) == 0:
		return "Keine Daten, kein Notenspiegel."

	output = list()
	Kurse, benoteteKurse = 0, 0
	sum_ECTS = 0
	gradesList = list()
	dashes = 80

	output.append("")
	output.append(" NotenSpiegel")
	output.append("=" * dashes)
	for g in grades:
		(Nr, Name, Note, ECTS) = (g['EDV_Nr'], g['Name'], g['Note'], g['ECTS'])
		if Note:
			benoteteKurse += 1
			sum_ECTS += ECTS
			gradesList.append( ECTS * Note )
			Note = "%2.2f" % Note
		else:
			Note = "n/a"
		Kurse += 1
		output.append(" %d %-30s : %5s (%d ECTS)" % (Nr, Name, Note, ECTS) )
	output.append("-" * dashes)
	gradesSum = math.fsum(gradesList)
	output.append(" Veranstaltungen: %2d von %2d benotet, erreichte ECTS: %d, Schnitt: %2.3f" % (benoteteKurse, Kurse, sum_ECTS, gradesSum / sum_ECTS)) 
	output.append("")
	return "\n".join(output)

def logTraceback(message, e, uselog=None):
	"""
	Exception traceback ausgeben.
	"""
	global log
	if uselog == None:
		uselog = log
	exceptionType, exceptionValue, exceptionTraceback = sys.exc_info()
	uselog.warning(message)
	uselog.error(e)
	tbList = traceback.format_exception(exceptionType, exceptionValue, exceptionTraceback)
	for line in tbList:
		for part in line.strip().split("\n"):
			if part != '':
				uselog.debug(part)

class Qis:
	ROOT_URL = "/qisserver/rds?"
	USER_AGENT = "qistool/1.0"

	def _dumpBody(self, body):
		for line in filter(lambda x: x.strip() != '', body.split("\n")):
			self.log.debug(re.sub("\s+", " ", line))

	def _shortenUrl(self, url):
		"""
		Eine URL verkuerzen, falls sie mit qis_server beginnt.
		"""
		if url.startswith("https://"):
			url = url[8:]
		if url.startswith(self.qis_server):
			url = url[len(self.qis_server):]
		return url

	def _request(self, method='GET', url='/', body='', headers=dict()):
		"""
		HTTP Request absenden.
		"""
		rContent, rHeaders, rSessionId, response = None, None, None, None

		method = method.upper()
		status = -1
		dashes = 30
		fmtString =  '%s' % ("=" * dashes) + ' Request %02d '   + '%s' % ("=" * dashes)
		fmtString2 = '%s' % ("-" * dashes) + ' Status %02d %s ' + '%s' % ("-" * dashes)

		self.log.debug(fmtString % self.requestCounter)
		self.log.debug("%s %s%s" % (method, self.qis_server, self._shortenUrl(url)))

		try:
			if len(headers) and self.verbose > 1:
				self.log.debug(">>>> HEADERS:")
				for key in headers:
					self.log.debug(" %-16s : '%s'" % (key, headers[key]))
		except Exception, e:
			logTraceback("(printing header)", e)

		try:
			if len(body) and self.verbose > 2:
				self.log.debug(">>>> BODY:")
				self.log.debug(" " + body)
		except Exception, e:
			logTraceback("(printing body)", e)

		try:
			headers["Accept-Encoding"] = "gzip,deflate"
			headers["Accept-Charset"] = "UTF-8,*"
			if Qis.USER_AGENT:
				headers["User-Agent"] = Qis.USER_AGENT

			self.conn.request(method, url, body, headers)
			response = self.conn.getresponse()
			rHeaders = response.getheaders()
			rSessionId = response.getheader('set-cookie', None)

			rBody = response.read()
			if response.getheader('content-encoding', 'naa').strip() == 'gzip':
				stream = StringIO(rBody)
				decompressor = GzipFile(fileobj=stream)
				rBody = decompressor.read()
			rContent = rBody.decode("utf-8")

			if rSessionId != None:
				try:
					rSessionId = rSessionId.split(";", 1)[0].strip()
					self.log.debug("++++ NEW  Session-Cookie: %s" % rSessionId)
				except Exception, e:
					logTraceback("(parsing rSessionId)", e)
			elif "Cookie" in headers:
				rSessionId = headers['Cookie']
				self.log.debug("#### KEEP Session-Cookie: %s" % rSessionId)

			status = response.status
			self.log.debug(fmtString2 % (status, response.reason))
		except Exception, e:
			logTraceback("Request '%s' FAILED" % url, e)
			raise Exception("Request '%s' FAILED" % url)

		try:
			if len(rHeaders) and self.verbose > 1:
				self.log.debug("<<<< HEADERS:")
				for (header, value) in rHeaders:
					self.log.debug(" %-16s : '%s'" % (header, value))
		except Exception, e:
			logTraceback("(printing rHeaders)", e)

		try:
			if len(rContent) and self.verbose > 2:
				self.log.debug("<<<< BODY:")
				self._dumpBody(rContent)
		except Exception, e:
			logTraceback("(printing rContent)", e)

		self.log.debug(fmtString % self.requestCounter)
		self.log.debug("")

		self.requestCounter += 1
		if status == 302:
			redirectUrl = response.getheader("location")
			self.log.debug("REDIRECT %s" % self._shortenUrl(redirectUrl))
			self.log.debug("")
			redirectHeaders = { 
						'Cookie'			: rSessionId,
					}
			return self._request(url=redirectUrl, headers=redirectHeaders)

		return (rContent, rHeaders, rSessionId)

	def _getSession(self):
		"""
		HTTP Request ausfuehren, um SessionId zu erhalten.
		Letztere muss immer mitgesendet werden, damit die Noten auch tatsaechlich
		abgerufen werden koennen.
		"""
		if self.verbose:
			self.log.info("SESSION")

		# Anmeldeseite aufrufen um die Sessionid rauszufinden
		getSessionDict = { 
						'state'				: 'user',
						'type'				: '0',
		}

		getSessionUrl = self.ROOT_URL + urllib.urlencode(getSessionDict)
		(rContent, rHeaders, rSessionId) = self._request(url=getSessionUrl)

		if rSessionId == None:
			raise Exception("Could not get rSessionId")

		return rSessionId

	def _doLogin(self, rSessionId, qis_user, qis_password):
		"""
		QIS-Login mit *qis_user* und *qis_password* durchfuehren.
		"""
		if self.verbose:
			self.log.info("LOGIN")

		loginUrlDict = {
						'state'				: 'user',
						'type'				: '1',
						'category'			: 'auth.login',
						'startpage'			: 'portal.vm',
						'breadCrumbSource'	: 'portal',
		}

		# seltsame Bezeichnungen fuer username und password respektieren:
		#USERNAME_ID = "username"
		USERNAME_ID = "asdf"
		#PASSWORD_ID = 'password'
		PASSWORD_ID = 'fdsa'

		loginDict = {
						USERNAME_ID 		: qis_user, 
						PASSWORD_ID 		: qis_password, 
						'submit' 			: 'Anmelden'
		}

		loginBody = urllib.urlencode(loginDict)
		loginHeaders = { 
						'Cookie'			: rSessionId,
						'Content-Type'		: 'application/x-www-form-urlencoded',
						'Content-Length'	: len(loginBody)
		}

		doLoginUrl = self.ROOT_URL + urllib.urlencode(loginUrlDict)
		(rContent, rHeaders, rSessionId) = self._request('POST', doLoginUrl, loginBody, loginHeaders)

		found = re.search(";asi=(.*?)\"", rContent)
		if found:
			asi = found.group(1)
			if self.verbose > 1:
				self.log.debug("asi=%s" % asi)
		else:
			self.log.error("No asi found")
			raise Exception("Login failed.")

		return(rSessionId, asi)

	def _doLogout(self, rSessionId):
		"""
		Logout-Request durchfuehren. Die Verbindung, Session zum QIS-Server wird beendet.
		"""
		if self.verbose:
			self.log.info("LOGOUT")

		logoutUrlDict = {
							'state'				: 'user',
							'category'			: 'auth.logout',
							'type'				: '4',
							'menuid'			: 'logout',
		}

		logoutHeaders = { 
							'Cookie'			: rSessionId,
		}

		doLogoutUrl = self.ROOT_URL + urllib.urlencode (logoutUrlDict)
		self._request(url=doLogoutUrl, headers=logoutHeaders)

	def _getGradesContent(self, rSessionId, asi):
		"""
		Noten abrufen.
		"""
		if self.verbose:
			self.log.info("GET GRADES")

		notenspiegelUrlDict = {
							'state'				: 'htmlbesch',
							'moduleParameter'	: 'Student',
							'menuid'			: 'notenspiegel',
							'asi'				: asi
		}

		notenspiegelHeaders = { 
							'Cookie'			: rSessionId,
		}

		doNotenspiegelUrl = self.ROOT_URL + urllib.urlencode (notenspiegelUrlDict)
		(rContent, rHeaders, rSessionId) = self._request(url=doNotenspiegelUrl, headers=notenspiegelHeaders)
		return(rSessionId, rContent)

	def getGrades(self, useSSL=True):
		"""
		Kompletter Notenabruf: 
			* SessionId abrufen
			* Login durchfuehren, asi Id erhalten
			* Noten abrufen
			* Logout
		"""
		start = datetime.datetime.now()
		self.requestCounter = 0
		if useSSL:
			self.conn = httplib.HTTPSConnection(self.qis_server)
		else:
			msg = "UNGESICHERTE HTTP VERBINDUNG!"
			self.log.warn(msg)
			weiter = raw_input(msg + " Trotzdem weiter? Bitte 'JA' eintippen.\n")
			if weiter != 'JA':
				sys.exit(99)
			self.conn = httplib.HTTPConnection(self.qis_server)
		rSessionId = self._getSession()
		rSessionId, asi = self._doLogin(rSessionId, self.qis_user, self.qis_password)
		rSessionId, content = self._getGradesContent(rSessionId, asi)
		self._doLogout(rSessionId)
		self.conn.close()
		duration = datetime.datetime.now() - start
		self.log.debug("Request time: %s" % duration)
		return parseGrades(content)

	def __init__(self, qis_user, qis_password, qis_server='vw-online.hdm-stuttgart.de', verbose=0, logLevel=None):
		self.qis_server = qis_server
		self.qis_user = qis_user
		self.qis_password = qis_password
		self.verbose = verbose
		self.log = logging.getLogger("qis.Qis")
		if logLevel:
			self.log.setLevel(logLevel)
			global log
			log = self.log
		self.log.debug("logLevel=%s verbose=%d" % (logLevel, self.verbose))

def interaktiv():
	qis_server='vw-online.hdm-stuttgart.de'

	print("\nHdM Notenspiegel qistool")
	print("** Benutzername und Passwort werden per SSL-Verbindung uebertragen")
	print("** (und natuerlich nur an den HdM-QIS Server: %s !)" % qis_server)
	print

	if HAVE_BeautifulSoup == False:
		lines = ["Das Python-Modul ''Beautiful Soup'' wird zur Verarbeitung des HTML-Inputs benoetigt.", 
				"URL: http://www.crummy.com/software/BeautifulSoup/", 
				"Installation:","\teasy_install BeautifulSoup", "oder", "\tapt-get install python-beautifulsoup"]
		print "\n".join(lines)
		sys.exit(1)

	username = raw_input("Bitte gib Dein HdM-Kuerzel ein: ")
	password = getpass.getpass("Passwort:")
	qis = Qis(qis_user=username, qis_password=password, qis_server=qis_server)
	grades = sorted(qis.getGrades(), cmp=sortGrades)
	print formatGrades(grades)

if __name__ == '__main__':
	interaktiv()