#!/usr/bin/python
# -*- coding: utf-8 -*-
import logging, sys, os
from config import qis_user, qis_password
from qis import *

if (not qis_user) or (not qis_password):
  config_abs = os.path.abspath("config.py")
  qis_abs = os.path.abspath("qis.py")
  
  lines = ["Bitte", "\t'%s'" % config_abs, "editieren und qis_user sowie qis_password setzen.", '', 
  "Oder fuer den interaktiven Modus", "\t'%s'" % qis_abs, 
  "direkt aufrufen - Benutzername und Passwort wrden dann abgefragt und nicht gespeichert.",
  '',
  "Starte nun den interaktiven Modus ...", '' ]
  print("\n".join(lines))
  interaktiv()
  sys.exit(123)
else:
  qis = Qis(qis_user=qis_user, qis_password=qis_password, verbose=0, logLevel=logging.INFO)
  grades = sorted(qis.getGrades(), cmp=sortGrades)
  print formatGrades(grades)
