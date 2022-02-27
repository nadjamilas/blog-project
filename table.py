from flask import Flask, render_template, redirect, url_for, flash, request, abort
from main import db
db.create_all()
