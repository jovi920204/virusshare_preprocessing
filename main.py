import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import os
import math
from PIL import Image

def read_file_to_csv():
    md5 = []
    avclass = []
    avclass_label = []
    with open('VirusShare_00313.avclass', 'r') as file:
        lines = file.readlines()
        for line in lines:
            tmp = line.split()
            md5.append(tmp[0])
            avclass.append(tmp[1])
            avclass_label.append(tmp[2])
    with open('VirusShare_00320.avclass', 'r') as file:
        lines = file.readlines()
        for line in lines:
            tmp = line.split()
            md5.append(tmp[0])
            avclass.append(tmp[1])
            avclass_label.append(tmp[2])
    
    class_title = []
    df = pd.DataFrame({'md5': md5, 'avclass': avclass, 'avclass_label': avclass_label})
    class_title = df['avclass'].value_counts(normalize=True).head(25).index.tolist()
    df = df[df['avclass'].isin(class_title)]
    df.to_csv('virusshare_313320.csv', index=False)

def plot_virusshare_313320():
    df = pd.read_csv('virusshare_313320.csv')
    class_title = df['avclass'].value_counts(normalize=True).head(25).index.tolist()
    df = df[df['avclass'].isin(class_title)]
    df['avclass'].value_counts().plot(kind='bar')
    plt.show()

def getBinaryData(filename):
	"""
	Extract byte values from binary executable file and store them into list
	:param filename: executable file name
	:return: byte value list
	"""

	binary_values = []

	with open(filename, 'rb') as fileobject:

		# read file byte by byte
		data = fileobject.read(1)

		while data != b'':
			binary_values.append(ord(data))
			data = fileobject.read(1)

	return binary_values

def get_size(data_length, width=None):
	# source Malware images: visualization and automatic classification by L. Nataraj
	# url : http://dl.acm.org/citation.cfm?id=2016908

	if width is None: # with don't specified any with value

		size = data_length

		if (size < 10240):
			width = 32
		elif (10240 <= size <= 10240 * 3):
			width = 64
		elif (10240 * 3 <= size <= 10240 * 6):
			width = 128
		elif (10240 * 6 <= size <= 10240 * 10):
			width = 256
		elif (10240 * 10 <= size <= 10240 * 20):
			width = 384
		elif (10240 * 20 <= size <= 10240 * 50):
			width = 512
		elif (10240 * 50 <= size <= 10240 * 100):
			width = 768
		else:
			width = 1024

		height = int(size / width) + 1

	else:
		width  = int(math.sqrt(data_length)) + 1
		height = width

	return (width, height)

def save_file(filename, data, size, image_type, avclass=None):

	try:
		image = Image.new(image_type, size)
		image.putdata(data)

		# setup output filename
		dirname     = os.path.dirname(filename)
		name, _     = os.path.splitext(filename)
		name        = os.path.basename(name)
		imagename   = 'imgs' + os.sep + avclass + os.sep + name + '.png'
		os.makedirs(os.path.dirname(imagename), exist_ok=True)

		image.save(imagename)
		print('The file', imagename, 'saved.')
	except Exception as err:
		print(err)

def createGreyScaleImage(filename, width=None, avclass=None):
	"""
	Create greyscale image from binary data. Use given with if defined or create square size image from binary data.
	:param filename: image filename
	"""
	greyscale_data  = getBinaryData(filename)
	size            = get_size(len(greyscale_data), width)
	save_file(filename, greyscale_data, size, 'L', avclass)


def preprocessing(malware_dir='malwares', img_dir='imgs'):
    # read csv
    df = pd.read_csv('virusshare_313320.csv')
    for i in range(len(df)):
        md5 = df.loc[i, 'md5']
        avclass = df.loc[i, 'avclass']
        malware_dir = os.path.join('malwares', md5)
        img_dir = os.path.join('imgs', avclass)
        if not os.path.exists(malware_dir):
            print('Malware not found: ', md5)
        else:
            if not os.path.exists(img_dir):
                os.makedirs(img_dir)
            # convert malware to image
            createGreyScaleImage(malware_dir, avclass=avclass)
			
if __name__ == '__main__':
	root_dir = os.getcwd()
	input_dir = os.path.join(root_dir, 'malwares')
	output_dir = os.path.join(root_dir, 'imgs')
	preprocessing(input_dir, output_dir)