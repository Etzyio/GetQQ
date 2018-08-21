from ctypes import *
__author__ = 'Etzyio'

dll = cdll.LoadLibrary('getqq.dll')
dll.getqq()
