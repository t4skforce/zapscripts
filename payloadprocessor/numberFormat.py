# Script to format numbers with leading zero

def process(payload):
	return '%08d' % (int(payload),)