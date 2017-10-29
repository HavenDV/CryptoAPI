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
    bool encryptFile(const QString & path);
    bool decryptFile(const QString & path);
    void exitFile();
    void exitSignMessage(bool err = true);
    void statusMessage(QString message, bool success = false);
    bool signMessage();
    bool verifySignedMessage();
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
    HCRYPTPROV hCryptProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;
    PBYTE pbBuffer, pbSignBuffer;

    HCERTSTORE hCertStore;
    PCCERT_CONTEXT pSignerCert;
    BYTE  *pbSignedMessageBlob;

};

#endif // MAINWINDOW_H
