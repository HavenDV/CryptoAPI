#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <cryptuiapi.h>
#include <QMainWindow>
#include <QFileDialog>
#include <QMessageBox>
#include <QDebug>

#define KEYLENGTH  0x00800000
#define ENCRYPT_ALGORITHM CALG_RC4
#define ENCRYPT_BLOCK_SIZE 8

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

//#define SIGNER_NAME L"Test"
#define CERT_STORE_NAME  L"MY"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    bool myEncryptFile();
    bool myDecryptFile();
    void exitFile();
    void exitSignMessage(bool err = true);
    void getEncrData();
    void myStatusMessage(QString message, bool success = false);
    bool mySignMessage();
    bool myVerifySignedMessage();
    void displayModifiedText(BYTE *pb, DWORD cb);

private slots:
    void on_encrypt_pushButton_clicked();

    void on_decrypt_pushButton_clicked();

    void on_sign_pushButton_clicked();

    void on_verify_pushButton_clicked();

    void on_choose_file1_pushButton_clicked();

    void on_choose_file2_pushButton_2_clicked();

    void on_choose_cert_pushButton_clicked();

    void on_message_pushButton_clicked();

    void on_sign_pushButton_2_clicked();

private:
    Ui::MainWindow *ui;
    QString source, destination, password;
    LPTSTR pszSourceFile, pszDestinationFile, pszPassword;
	HANDLE hSourceFile;
	HANDLE hDestinationFile;
    HCRYPTPROV hCryptProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;
    PBYTE pbBuffer, pbSignBuffer;

    QString rawText, modifiedText;
    HCERTSTORE hCertStore;
    PCCERT_CONTEXT pSignerCert;
    BYTE  *pbSignedMessageBlob;
    DWORD cbSignedMessageBlob;

    CRYPT_SIGN_MESSAGE_PARA SigParams;
    CRYPT_VERIFY_MESSAGE_PARA VerifyParams;
};

#endif // MAINWINDOW_H
