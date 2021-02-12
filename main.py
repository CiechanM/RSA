from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
import time, sys, traceback, random, re, tkinter, numpy, os
from tkinter import filedialog
from PIL import Image

from rsaGenerator import RSAgenerator

root = tkinter.Tk()
root.withdraw()

filePath = ""
codePath = ""

txtregex = re.compile("^.*\.txt$")
bitmapregex = re.compile("^.*\.bmp$")


class Okno(QMainWindow):
    def __init__(self, *args, **kwargs):
        super(Okno, self).__init__(*args, *kwargs)
        self.setWindowTitle("ALGORYTM RSA")

        titleText = QLabel()
        titleText.setText("ALGORYTM RSA")
        titleText.setAlignment(Qt.AlignCenter)
        titleText.setFont(QFont('Courier New', 40))
        titleText.setStyleSheet("QLabel {color: #1B2A41} ")

        encryptionText = QLabel()
        encryptionText.setText("ENCRYPTION")
        encryptionText.setAlignment(Qt.AlignCenter)
        encryptionText.setFont(QFont('Courier New', 20))
        encryptionText.setStyleSheet("QLabel {color: #1B2A41} ")

        decryptionText = QLabel()
        decryptionText.setText("-------------------------------------------------"
                               "\nDECRYPTION")
        decryptionText.setAlignment(Qt.AlignCenter)
        decryptionText.setFont(QFont('Courier New', 20))
        decryptionText.setStyleSheet("QLabel {color: #1B2A41} ")


        selectImageButton = QPushButton()
        selectImageButton.setText("CHOOSE FILE FOR ENCRYPTION")
        selectImageButton.setFont(QFont('Courier New', 12))
        selectImageButton.setStyleSheet("QPushButton {background : #1B2A41}")
        selectImageButton.setStyleSheet("QPushButton {color : #1B2A41}")
        selectImageButton.clicked.connect(lambda: self.chooseFileClicked(1))


        selectImageButton2 = QPushButton()
        selectImageButton2.setText("CHOOSE PUBLIC KEY")
        selectImageButton2.setFont(QFont('Courier New', 12))
        selectImageButton2.setStyleSheet("QPushButton {background : #1B2A41}")
        selectImageButton2.setStyleSheet("QPushButton {color : #1B2A41}")
        selectImageButton2.clicked.connect(lambda: self.chooseFileClicked(2))

        encryptButtonsLayout = QHBoxLayout()
        encryptButtonsLayout.addWidget(selectImageButton)
        encryptButtonsLayout.addWidget(selectImageButton2)
        encryptButtonsLayoutWidget = QWidget()
        encryptButtonsLayoutWidget.setLayout(encryptButtonsLayout)

        generateButton = QPushButton()
        generateButton.setText("GENERATE KEYS")
        generateButton.setFont(QFont('Courier New', 12))
        generateButton.clicked.connect(self.generateClicked)

        selectDecryptButton1 = QPushButton()
        selectDecryptButton1.setText("CHOOSE FILE FOR DECRYPTION")
        selectDecryptButton1.setFont(QFont('Courier New', 12))
        selectDecryptButton1.setStyleSheet("QPushButton {background : #1B2A41}")
        selectDecryptButton1.setStyleSheet("QPushButton {color : #1B2A41}")
        selectDecryptButton1.clicked.connect(lambda: self.chooseFileClicked(3))



        selectDecryptButton2 = QPushButton()
        selectDecryptButton2.setText("CHOOSE PRIVATE KEY")
        selectDecryptButton2.setFont(QFont('Courier New', 12))
        selectDecryptButton2.setStyleSheet("QPushButton {background : #1B2A41}")
        selectDecryptButton2.setStyleSheet("QPushButton {color : #1B2A41}")
        selectDecryptButton2.clicked.connect(lambda: self.chooseFileClicked(4))

        decryptButtonsLayout = QHBoxLayout()
        decryptButtonsLayout.addWidget(selectDecryptButton1)
        decryptButtonsLayout.addWidget(selectDecryptButton2)
        decryptButtonsLayoutWidget = QWidget()
        decryptButtonsLayoutWidget.setLayout(decryptButtonsLayout)


        self.textFromFileButton = QFileDialog()
        self.textFromFileButton.setNameFilter("Text (*.txt)")
        self.textFromFileButton.hide()

        self.pathText = QLabel()
        self.pathText.setText("*Path to file to encrypt*")
        self.pathText.setAlignment(Qt.AlignCenter)
        self.pathText.setFont(QFont('Courier New', 11))
        self.pathText.setStyleSheet("QPushButton {color : #1B2A41}")


        self.pathText2 = QLabel()
        self.pathText2.setText("*Path to public key for encryption*")
        self.pathText2.setAlignment(Qt.AlignCenter)
        self.pathText2.setFont(QFont('Courier New', 11))
        self.pathText2.setStyleSheet("QPushButton {color : #1B2A41}")

        pathButtonsLayout1 = QVBoxLayout()
        pathButtonsLayout1.addWidget(self.pathText)
        pathButtonsLayout1.addWidget(self.pathText2)
        pathButtonsLayoutWidget1 = QWidget()
        pathButtonsLayoutWidget1.setLayout(pathButtonsLayout1)

        self.pathDecrypt1Text = QLabel()
        self.pathDecrypt1Text.setText("*Path to file to decrypt*")
        self.pathDecrypt1Text.setAlignment(Qt.AlignCenter)
        self.pathDecrypt1Text.setFont(QFont('Courier New', 11))
        self.pathDecrypt1Text.setStyleSheet("QPushButton {color : #1B2A41}")


        self.pathDecrypt2Text = QLabel()
        self.pathDecrypt2Text.setText("*Path to private key for decryption*")
        self.pathDecrypt2Text.setAlignment(Qt.AlignCenter)
        self.pathDecrypt2Text.setFont(QFont('Courier New', 11))
        self.pathDecrypt2Text.setStyleSheet("QPushButton {color : #1B2A41}")

        pathButtonsLayout = QVBoxLayout()
        pathButtonsLayout.addWidget(self.pathDecrypt1Text)
        pathButtonsLayout.addWidget(self.pathDecrypt2Text)
        pathButtonsLayoutWidget = QWidget()
        pathButtonsLayoutWidget.setLayout(pathButtonsLayout)

        infoButton = QPushButton()
        infoButton.setFont(QFont('Courier New', 11))
        infoButton.setStyleSheet("QPushButton {background : #1B2A41}")
        infoButton.setStyleSheet("QPushButton {color : #1B2A41}")
        infoButton.setText("INFO")
        infoButton.clicked.connect(self.infoClicked)

        helpButton = QPushButton()
        helpButton.setFont(QFont('Courier New', 11))
        helpButton.setStyleSheet("QPushButton {background : #1B2A41}")
        helpButton.setStyleSheet("QPushButton {color : #1B2A41}")
        helpButton.setText("HELP")
        helpButton.clicked.connect(self.helpClicked)


        ##############################
        encryptButton = QPushButton()
        encryptButton.setText("ENCRYPT")
        encryptButton.setFont(QFont('Courier New',12))
        encryptButton.setStyleSheet("QPushButton {background : #1B2A41}")
        encryptButton.setStyleSheet("QPushButton {color : #1B2A41}")
        encryptButton.clicked.connect(self.encryptClicked)

        decryptButton = QPushButton()
        decryptButton.setText("DECRYPT")
        decryptButton.setFont(QFont('Courier New', 12))
        decryptButton.setStyleSheet("QPushButton {background : #1B2A41}")
        decryptButton.setStyleSheet("QPushButton {color : #1B2A41}")
        decryptButton.clicked.connect(self.decryptClicked)

        buttonsLayout = QHBoxLayout()
        buttonsLayout.addWidget(encryptButton)
        buttonsLayout.addWidget(decryptButton)
        buttonsLayoutWidget = QWidget()
        buttonsLayoutWidget.setLayout(buttonsLayout)



        ############
        self.noiseButton = QRadioButton("NOISE DECRYPTION")
        self.cleanButton = QRadioButton("CLEAN DECRYPTION")
        self.noiseButton.setChecked(True)

        modeButtonsLayout = QHBoxLayout()
        modeButtonsLayout.addWidget(self.noiseButton)
        modeButtonsLayout.addWidget(self.cleanButton)
        modeButtonsLayout.setAlignment(Qt.AlignHCenter)
        modeButtonsLayoutWidget = QWidget()
        modeButtonsLayoutWidget.setLayout(modeButtonsLayout)

        # Width mode
        self.wideButtonD = QRadioButton("WIDE")
        self.originalButtonD = QRadioButton("ORIGINAL SIZE")
        self.originalButtonD.setChecked(True)

        widthButtonsLayoutD = QHBoxLayout()
        widthButtonsLayoutD.addWidget(self.originalButtonD)
        widthButtonsLayoutD.addWidget(self.wideButtonD)
        widthButtonsLayoutD.setAlignment(Qt.AlignHCenter)
        widthButtonsLayoutDWidget = QWidget()
        widthButtonsLayoutDWidget.setLayout(widthButtonsLayoutD)

        #######################################


        topLayout = QHBoxLayout()
        topLayout.addWidget(infoButton)
        topLayout.addWidget(helpButton)
        topLayoutWidget = QWidget()
        topLayoutWidget.setLayout(topLayout)



        ################

        self.originalButton = QRadioButton("ORIGINAL SIZE")
        self.wideButton = QRadioButton("WIDE")
        self.originalButton.setChecked(True)

        widthButtonsLayout = QHBoxLayout()
        widthButtonsLayout.addWidget(self.originalButton)
        widthButtonsLayout.addWidget(self.wideButton)
        widthButtonsLayout.setAlignment(Qt.AlignHCenter)
        widthButtonsLayoutWidget = QWidget()
        widthButtonsLayoutWidget.setLayout(widthButtonsLayout)
########################################################
        mainMenu = QVBoxLayout()
        mainMenu.addWidget(titleText)

        # encryption
        mainMenu.addWidget(encryptionText)
        mainMenu.addWidget(generateButton)
        mainMenu.addWidget(pathButtonsLayoutWidget1)
        mainMenu.addWidget(encryptButtonsLayoutWidget)
        #mainMenu.addWidget(widthButtonsLayoutWidget)
        mainMenu.addWidget(encryptButton)


        # decryption
        mainMenu.addWidget(decryptionText)
        mainMenu.addWidget(pathButtonsLayoutWidget)
        #mainMenu.addWidget(self.pathDecrypt2Text)
        mainMenu.addWidget(decryptButtonsLayoutWidget)
        #mainMenu.addWidget(modeButtonsLayoutWidget)
        #mainMenu.addWidget(widthButtonsLayoutDWidget)
        mainMenu.addWidget(decryptButton)


        #mainMenu.addWidget(buttonsLayoutWidget)

        mainMenu.addWidget(topLayoutWidget)

        mainMenuWidget = QWidget()
        mainMenuWidget.setLayout(mainMenu)

        self.setCentralWidget(mainMenuWidget)


    def infoClicked(self):
        f = open("info.txt", "r", encoding="utf8")
        infoText = f.read()
        QMessageBox.about(self, "INFO", infoText)

    def helpClicked(self):
        f = open("help.txt", "r", encoding="utf8")
        helpText = f.read()
        QMessageBox.about(self, "HELP", helpText)

    def generateClicked(self):
        """Generate keys"""

        self.rsaGenerator = RSAgenerator()
        filename = QFileDialog.getSaveFileName(self, "Open Text File", os.path.abspath(os.getcwd()),
                                               "Text Files (*.txt)")
        if filename[0] != '':
            dir = filename[0]
            i = len(dir) - 1
            while True:
                dir = dir[:-1]
                i -= 1
                if dir[i] == '.':
                    dir = dir[:-1]
                    break
            dir1 = dir + '_private.txt'
            dir2 = dir + '_public.txt'
            with open(dir1, "w") as outputfile:
                outputfile.write(str(self.rsaGenerator.privateKey()))
            with open(dir2, "w") as outputfile:
                outputfile.write(str(self.rsaGenerator.publicKey()))

        #ENCRYPTION

    def chooseFileClicked(self, num):
        """Sets file path"""
        self.textFromFileButton.show()

        if self.textFromFileButton.exec():
            files = self.textFromFileButton.selectedFiles()
            if num == 1:
                self.pathText.setText(files[0])
            if num == 2:
                self.pathText2.setText(files[0])
            if num == 3:
                self.pathDecrypt1Text.setText(files[0])
            if num == 4:
                self.pathDecrypt2Text.setText(files[0])

    def widthState(self):
        """Checks which width was chosen. false if original, true if wide"""
        if self.wideButton.isChecked():
            return True
        else:
            return False

    def encryptClicked(self):

        with open(self.pathText.text(), "r") as fileinput:
            data = fileinput.read()
        with open(self.pathText2.text(), "r") as fileinput:
            publicKey = fileinput.read()
        publicKey = re.sub(r'[^0-9 ]+', '', publicKey).split()

        asciiText = [ord(letter) for letter in data]
        encrypted = [RSAgenerator.power(letter, int(publicKey[0]), int(publicKey[1])) for letter in asciiText]

        filename = QFileDialog.getSaveFileName(self, "Open Text File", os.path.abspath(os.getcwd()),
                                               "Text Files (*.txt)")
        with open(filename[0], "w") as outputfile:
            for x in encrypted:
                outputfile.write(str(x) + " ")

    #########decrypt


    def selectDecryptImageClicked(self, num):
        """Sets file path"""
        self.imageFromFileButton.show()

        if self.imageFromFileButton.exec():
            files = self.imageFromFileButton.selectedFiles()
            if num == 1:
                self.pathDecrypt1Text.setText(files[0])
            else:
                self.pathDecrypt2Text.setText(files[0])


    def decryptClicked(self):
        with open(self.pathDecrypt1Text.text(), "r") as file:
            text = file.read()
        text = text.split()
        for i in range(len(text)):
            text[i] = int(text[i])

        with open(self.pathDecrypt2Text.text(), "r") as fileinput:
            privateKey = fileinput.read()
        privateKey = re.sub(r'[^0-9 ]+', '', privateKey).split()

        text = [RSAgenerator.power(c, int(privateKey[0]), int(privateKey[1])) for c in text]
        text2 = ""
        for letter in text:
            if letter in range(0x110000):
                text2 += chr(letter)
            else:
                return

        filename = QFileDialog.getSaveFileName(self, "Open Text File", os.path.abspath(os.getcwd()),
                                               "Text Files (*.txt)")
        with open(filename[0], "w") as outputfile:
            for x in text2:
                outputfile.write(str(x))

# MAIN
app = QApplication(sys.argv)

window = Okno()
window.setFixedSize(800, 600)
window.setStyleSheet("background-color:  #CCC9DC ;")
window.show()

app.exec_()