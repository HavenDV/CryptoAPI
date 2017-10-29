#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

bool MainWindow::encryptFile(const QString & path)
{
	auto destination = path + ".detsf";

	QFile sourceFile(path);
	if (!sourceFile.open(QIODevice::OpenModeFlag::ReadOnly))
	{
        statusMessage(trUtf8("Ошибка открытия файла для чтения\n") + sourceFile.errorString());
        return false;
    }

	QFile destinationFile(destination);
	if (!destinationFile.open(QIODevice::OpenModeFlag::Truncate | QIODevice::OpenModeFlag::WriteOnly))
	{
		statusMessage(trUtf8("Ошибка открытия  файла для записи\n") + sourceFile.errorString());
		return false;
	}

    if (!CryptAcquireContext(&hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0)) {

        statusMessage(trUtf8("Ошибка получения дескриптора к контейнеру ключей\nCryptAcquireContext error"));
        exitFile();
        return false;
    }

	HCRYPTKEY hXchgKey = NULL;
	PBYTE pbKeyBlob = NULL;
	DWORD dwKeyBlobLen;
	DWORD dwBlockLen;
	DWORD dwBufferLen;
	auto pszPassword = (wchar_t*)ui->password_lineEdit->text().utf16();
    if (!pszPassword || !pszPassword[0]) {

        if(!CryptGenKey(hCryptProv, ENCRYPT_ALGORITHM, KEYLENGTH | CRYPT_EXPORTABLE, &hKey)) {

            statusMessage(trUtf8("Ошибка генерации ключа\nCryptGenKey error"));
            exitFile();
            return false;
        }
        if (!CryptGetUserKey(hCryptProv, AT_KEYEXCHANGE, &hXchgKey)) {

            if (NTE_NO_KEY == GetLastError()) {

                if (!CryptGenKey(hCryptProv, AT_KEYEXCHANGE, CRYPT_EXPORTABLE, &hXchgKey)) {

                    statusMessage(trUtf8("Ошибка создания пользовательского открытого ключа\nCryptGenKey error"));
                    exitFile();
                    return false;
                }
            }
            else {

                statusMessage(trUtf8("Открытый пользовательский ключ недоступен или не существует\nCryptGetUserKey error"));
                exitFile();
                return false;
            }
        }

        if (!CryptExportKey(hKey, hXchgKey, SIMPLEBLOB, 0, NULL, &dwKeyBlobLen)) {

            statusMessage(trUtf8("Ошибка вычисления длины BLOB для экспорта ключа\nCryptExportKey error"));
            exitFile();
            return false;
        }

        if (!(pbKeyBlob = (BYTE *)malloc(dwKeyBlobLen))) {

            statusMessage(trUtf8("Недостаточно памяти под BLOB ключ\nmalloc error"));
            exitFile();
            return false;
        }

        if (!CryptExportKey(hKey, hXchgKey, SIMPLEBLOB, 0, pbKeyBlob, &dwKeyBlobLen)) {

            statusMessage(trUtf8("Ошибка во время экспорта ключа\nCryptExportKey error"));
            exitFile();
            return false;
        }

        if (hXchgKey) {

            if (!(CryptDestroyKey(hXchgKey))) {

                statusMessage(trUtf8("Ошибка во время уничтожения ключа\nCryptDestroyKey error"));
                exitFile();
                return false;
            }
            hXchgKey = 0;
        }

		if (destinationFile.write((char *)&dwKeyBlobLen, sizeof(DWORD)) == 0) {
            statusMessage(trUtf8("Ошибка записи размера BLOB ключа в файл\nWriteFile error"));
            exitFile();
            return false;
        }

		if (destinationFile.write((char *)pbKeyBlob, dwKeyBlobLen) == 0) {
            statusMessage(trUtf8("Ошибка записи ключа в файл\nWriteFile error"));
            exitFile();
            return false;
        }

        free(pbKeyBlob);
    }
    else {

        if (!CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash)) {

            statusMessage(trUtf8("Ошибка создания хеш-объекта\nCryptCreateHash error"));
            exitFile();
            return false;
        }

        if (!CryptHashData(hHash, (BYTE *)pszPassword, lstrlen(pszPassword), 0)) {

            statusMessage(trUtf8("Ошибка хеширования пароля\nCryptHashData error"));
            exitFile();
            return false;
        }

        if (!CryptDeriveKey(hCryptProv, ENCRYPT_ALGORITHM, hHash, KEYLENGTH, &hKey)) {

            statusMessage(trUtf8("Ошибка создания ключа на основе пароля\nCryptDeriveKey error"));
            exitFile();
            return false;
        }
    }

    dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE;

    if (ENCRYPT_BLOCK_SIZE > 1)
        dwBufferLen = dwBlockLen + ENCRYPT_BLOCK_SIZE;
    else
        dwBufferLen = dwBlockLen;

    if (!(pbBuffer = (BYTE *)malloc(dwBufferLen))) {

        statusMessage(trUtf8("Недостаточно памяти под шифруемый блок данных\nmalloc error"));
        exitFile();
        return false;
    }

    bool fEOF = FALSE;
    do {
		DWORD dwCount = sourceFile.read((char*)pbBuffer, dwBlockLen);
        if (dwCount < dwBlockLen)
            fEOF = TRUE;

        if (!CryptEncrypt(hKey, NULL, fEOF, 0, pbBuffer, &dwCount, dwBufferLen)) {

            statusMessage(trUtf8("Ошибка шифрования блока данных\nCryptEncrypt error"));
            exitFile();
            return false;
        }

		if (destinationFile.write((char *)pbBuffer, dwCount) == 0) {
            statusMessage(trUtf8("Ошибка записи зашифрованного блока данных\nWriteFile error"));
            exitFile();
            return false;
        }
    } while(!fEOF);

    statusMessage(trUtf8("Все данные были успешно зашифрованы"), true);
    exitFile();
    return true;
}

bool MainWindow::decryptFile(const QString & path)
{
    hCryptProv = NULL;
    hKey = NULL;
    hHash = NULL;
    pbBuffer = NULL;

    DWORD dwCount;
    DWORD dwBlockLen;
    DWORD dwBufferLen;
    DWORD dwKeyBlobLen;
    PBYTE pbKeyBlob = NULL;

	auto pszSourceFile = (wchar_t*)path.utf16();
    HANDLE hSourceFile = CreateFile(pszSourceFile, FILE_READ_DATA, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (INVALID_HANDLE_VALUE == hSourceFile) {

        statusMessage(trUtf8("Ошибка открытия файла для чтения\nCreateFile error"));
        exitFile();
        return false;
    }

	auto destination = path + ".detsf";
	auto pszDestinationFile = (wchar_t*)destination.utf16();
    auto hDestinationFile = CreateFile(pszDestinationFile, FILE_WRITE_DATA, FILE_SHARE_READ,
            NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (INVALID_HANDLE_VALUE == hDestinationFile) {

        statusMessage(trUtf8("Ошибка открытия файла для записи\nCreateFile error"));
        exitFile();
        return false;
    }

    if (!CryptAcquireContext(&hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0)) {

        statusMessage(trUtf8("Ошибка получения дескриптора к контейнеру ключей\nCryptAcquireContext error"));
        exitFile();
        return false;
    }

	auto pszPassword = (wchar_t*)ui->password_lineEdit->text().utf16();
    if (!pszPassword || !pszPassword[0]) {

        if (!ReadFile(hSourceFile, &dwKeyBlobLen, sizeof(DWORD), &dwCount, NULL)) {

            statusMessage(trUtf8("Ошибка чтения размера BLOB ключа\nReadFile error"));
            exitFile();
            return false;
        }

        if (!(pbKeyBlob = (PBYTE)malloc(dwKeyBlobLen)))
            statusMessage(trUtf8("Ошибка выделения памяти под BLOB ключ\nmalloc error"));

        if (!ReadFile(hSourceFile, pbKeyBlob, dwKeyBlobLen, &dwCount, NULL)) {

            statusMessage(trUtf8("Ошибка чтения BLOB ключа из файла\nReadFile error"));
            exitFile();
            return false;
        }

        if (!CryptImportKey(hCryptProv, pbKeyBlob, dwKeyBlobLen, 0, 0, &hKey)) {

            statusMessage(trUtf8("Ошибка импорта ключа\nCryptImportKey error"));
            exitFile();
            return false;
        }

        if (pbKeyBlob)
            free(pbKeyBlob);
    }
    else {

        if (!CryptCreateHash(hCryptProv, CALG_MD5, 0, 0, &hHash)) {

            statusMessage(trUtf8("Ошибка создания хеш-объекта\nCryptCreateHash error"));
            exitFile();
            return false;
        }

        if (!CryptHashData(hHash, (BYTE *)pszPassword, lstrlen(pszPassword), 0)) {

            statusMessage(trUtf8("Ошибка хеширования пароля\nCryptHashData error"));
            exitFile();
            return false;
        }

        if (!CryptDeriveKey(hCryptProv, ENCRYPT_ALGORITHM, hHash, KEYLENGTH, &hKey)) {

            statusMessage(trUtf8("Ошибка создания ключа на основе пароля\nCryptDeriveKey error"));
            exitFile();
            return false;
        }
    }

    dwBlockLen = 1000 - 1000 % ENCRYPT_BLOCK_SIZE;
    dwBufferLen = dwBlockLen;

    if (!(pbBuffer = (PBYTE)malloc(dwBufferLen))) {

        statusMessage(trUtf8("Недостаточно памяти под дешифруемый блок данных\nmalloc error"));
        exitFile();
        return false;
    }

    bool fEOF = FALSE;
    do {

        if (!ReadFile(hSourceFile, pbBuffer, dwBlockLen, &dwCount, NULL)) {

            statusMessage(trUtf8("Ошибка чтения блока данных из файла\nReadFile error"));
            exitFile();
            return false;
        }

        if (dwCount <= dwBlockLen)
            fEOF = TRUE;

        if (!CryptDecrypt(hKey, NULL, fEOF, 0, pbBuffer, &dwCount)) {

            statusMessage(trUtf8("Ошибка дешифрования блока данных\nCryptEncrypt error"));
            exitFile();
            return false;
        }

        if (!WriteFile(hDestinationFile, pbBuffer, dwCount, &dwCount, NULL)) {

            statusMessage(trUtf8("Ошибка записи расшифрованного блока данных\nWriteFile error"));
            exitFile();
            return false;
        }
    } while(!fEOF);

    statusMessage(trUtf8("Все данные были успешно расшифрованы"), true);
    exitFile();
    return true;
}

void MainWindow::exitFile()
{
    if (pbBuffer)
        free(pbBuffer);

    if (hHash) {
        if (!(CryptDestroyHash(hHash)))
            statusMessage(trUtf8("Ошибка уничтожения хеш-объекта\nCryptDestroyHash error"));
        hHash = NULL;
    }

    if (hKey) {
        if (!(CryptDestroyKey(hKey)))
            statusMessage(trUtf8("Ошибка уничтожения сессионного ключа\nCryptDestroyKey error"));
    }

    if (hCryptProv) {
        if (!(CryptReleaseContext(hCryptProv, 0)))
            statusMessage(trUtf8("Ошибка уничтожения дескриптора к контейнеру ключей\nCryptReleaseContext error"));
    }
}

void MainWindow::exitSignMessage(bool err)
{
    if (pbBuffer)
        free(pbBuffer);

    if (pbSignBuffer)
        free(pbSignBuffer);

    if (pSignerCert)
        CertFreeCertificateContext(pSignerCert);

    if (hCertStore) {
        CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
        hCertStore = NULL;
    }

    if (err) {

        if (pbSignedMessageBlob) {

            free(pbSignedMessageBlob);
            pbSignedMessageBlob = NULL;
        }
    }    
}

void MainWindow::statusMessage(QString message, bool success)
{
    //ui->status_label->setText(message);
    if (success)
        QMessageBox::information(this, trUtf8("Операция выполнена успешно"), message);
    else
        QMessageBox::critical(this, trUtf8("Ошибка"), message);
}

bool MainWindow::signMessage()
{
    DWORD dwCount, dwSize = 0;
    pbBuffer = NULL, pbSignBuffer = NULL;
    hCertStore = NULL;
    pSignerCert = NULL;
    pbSignedMessageBlob = NULL;

    const wchar_t* certName = ui->choose_cert_lineEdit->text().toStdWString().c_str();

	auto source = ui->message_lineEdit->text();
    auto pszSourceFile = (wchar_t*)source.utf16();

    auto destination = source + ".detsf";
    auto pszDestinationFile = (wchar_t*)destination.utf16();

    qDebug() << "New signature file: " << destination;


    auto hSourceFile = CreateFile(pszSourceFile, FILE_READ_DATA, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (INVALID_HANDLE_VALUE == hSourceFile) {

        statusMessage(trUtf8("Ошибка открытия подписываемого файла\nCreateFile error"));
        exitSignMessage();
        return false;
    }

    auto hDestinationFile = CreateFile(pszDestinationFile, FILE_WRITE_DATA, FILE_SHARE_READ,
            NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (INVALID_HANDLE_VALUE == hDestinationFile) {

        statusMessage(trUtf8("Ошибка создания файла для хранения подписи\nCreateFile error"));
        exitSignMessage();
        return false;
    }

    dwSize = GetFileSize(hSourceFile, NULL);
    qDebug() << "Size of file to be signed: " << dwSize;

    if (!(pbBuffer = (BYTE *)malloc(dwSize))) {

        statusMessage(trUtf8("Недостаточно памяти под подписываемое собщение\nmalloc error"));
        exitSignMessage();
        return false;
    }

    if (!ReadFile(hSourceFile, pbBuffer, dwSize, &dwCount, NULL)) {

        statusMessage(trUtf8("Ошибка чтения подписываемого файла\nReadFile error"));
        exitSignMessage();
        return false;
    }

    const BYTE *MessageArray[] = {pbBuffer};
    DWORD_PTR MessageSizeArray[1];
    MessageSizeArray[0] = dwCount;

    if (!(hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0,
        NULL, CERT_SYSTEM_STORE_CURRENT_USER, CERT_STORE_NAME))) {

        statusMessage(trUtf8("Ошибка открытия хранилища сертификатов \"Личные\"\nCertOpenStore error"));
        exitSignMessage();
        return false;
    }

    if (!(pSignerCert = CertFindCertificateInStore(hCertStore, MY_ENCODING_TYPE,
        0, CERT_FIND_SUBJECT_STR, certName, NULL))) {

        statusMessage(trUtf8("Сертификат не найден\npSignerCert error"));
        exitSignMessage();
        return false;
    }

	CRYPT_SIGN_MESSAGE_PARA SigParams;
    SigParams.cbSize = sizeof (CRYPT_SIGN_MESSAGE_PARA);
    SigParams.dwMsgEncodingType = MY_ENCODING_TYPE;
    SigParams.pSigningCert = pSignerCert;
    SigParams.HashAlgorithm.pszObjId = (LPSTR)szOID_RSA_SHA1RSA;
    SigParams.HashAlgorithm.Parameters.cbData = NULL;
    SigParams.cMsgCert = 1;
    SigParams.rgpMsgCert = &pSignerCert;
    SigParams.cAuthAttr = 0;
    SigParams.dwInnerContentType = 0;
    SigParams.cMsgCrl = 0;
    SigParams.cUnauthAttr = 0;
    SigParams.dwFlags = 0;
    SigParams.pvHashAuxInfo = NULL;
    SigParams.rgAuthAttr = NULL;

	DWORD cbSignedMessageBlob = NULL;
    if (!CryptSignMessage(&SigParams, TRUE, 1, MessageArray, MessageSizeArray,
        NULL, &cbSignedMessageBlob)) {

        statusMessage(trUtf8("Ошибка получения размера BLOB подписи\nCryptSignMessage error"));
        exitSignMessage();
        return false;
    }

    if (!(pbSignedMessageBlob = (BYTE*)malloc(cbSignedMessageBlob))) {

        statusMessage(trUtf8("Недостаточно памяти под подпись\nmalloc error"));
        exitSignMessage();
        return false;
    }

    if (CryptSignMessage(&SigParams, TRUE, 1, MessageArray, MessageSizeArray,
        pbSignedMessageBlob, &cbSignedMessageBlob)) {

        if (!WriteFile(hDestinationFile, pbSignedMessageBlob, cbSignedMessageBlob, &dwCount, NULL)) {

            statusMessage(trUtf8("Ошибка записи подписи в файл\nWriteFile error"));
            exitSignMessage();
            return false;
        }

        statusMessage(trUtf8("Подпись создана успешно"), true);
        exitSignMessage(false);

        displayModifiedText(pbSignedMessageBlob, cbSignedMessageBlob);

        return true;
    }
    else {

        statusMessage(trUtf8("Ошибка создания подписи\nCryptSignMessage error"));
        exitSignMessage();
        return false;
    }
}

bool MainWindow::verifySignedMessage()
{
    DWORD dwCount, dwSize = 0;
    DWORD dwSignCount, dwSignSize = 0;
    pbBuffer = NULL, pbSignBuffer = NULL;
    hCertStore = NULL;
    pSignerCert = NULL;

    const wchar_t* certName = ui->choose_cert_lineEdit->text().toStdWString().c_str();

	auto source = ui->sign_lineEdit->text();
    auto pszSourceFile = (wchar_t*)source.utf16();

    auto hSourceFile = CreateFile(pszSourceFile, FILE_READ_DATA, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (INVALID_HANDLE_VALUE == hSourceFile) {

        statusMessage(trUtf8("Ошибка открытия файла с подписью\nCreateFile error"));
        exitSignMessage();
        return false;
    }

    dwSignSize = GetFileSize(hSourceFile, NULL);
    qDebug() << "Size of signature: " << dwSignSize;

    if (!(pbSignBuffer = (BYTE *)malloc(dwSignSize))) {

        statusMessage(trUtf8("Недостаточно памяти под подпись\nmalloc error"));
        exitSignMessage();
        return false;
    }

    if (!ReadFile(hSourceFile, pbSignBuffer, dwSignSize, &dwSignCount, NULL)) {

        statusMessage(trUtf8("Ошибка чтения подписи из файла\nReadFile error"));
        exitSignMessage();
        return false;
    }

    CloseHandle(hSourceFile);
    hSourceFile = INVALID_HANDLE_VALUE;

    source = ui->message_lineEdit->text();
    pszSourceFile = (wchar_t*)source.utf16();

    hSourceFile = CreateFile(pszSourceFile, FILE_READ_DATA, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (INVALID_HANDLE_VALUE == hSourceFile) {

        statusMessage(trUtf8("Ошибка открытия подписанного файла\nCreateFile error"));
        exitSignMessage();
        return false;
    }

    dwSize = GetFileSize(hSourceFile, NULL);
    qDebug() << "Size of signed file: " << dwSize;

    if (!(pbBuffer = (BYTE *)malloc(dwSize))) {

        statusMessage(trUtf8("Недостаточно памяти под подписанный файл\nmalloc error"));
        exitSignMessage();
        return false;
    }

    if (!ReadFile(hSourceFile, pbBuffer, dwSize, &dwCount, NULL)) {

        statusMessage(trUtf8("Ошибка чтения подписанных данных из файла\nReadFile error"));
        exitSignMessage();
        return false;
    }

    if (!(hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0,
        NULL, CERT_SYSTEM_STORE_CURRENT_USER, CERT_STORE_NAME))) {

        statusMessage(trUtf8("Ошибка открытия хранилища сертификатов \"Личные\"\nCertOpenStore error"));
        exitSignMessage();
        return false;
    }

    if (!(pSignerCert = CertFindCertificateInStore(hCertStore, MY_ENCODING_TYPE,
        0, CERT_FIND_SUBJECT_STR, certName, NULL))) {

        statusMessage(trUtf8("Сертификат не найден\npSignerCert error"));
        exitSignMessage();
        return false;
    }

    const BYTE *MessageArray[] = {pbBuffer};
    DWORD_PTR MessageSizeArray[1];
    MessageSizeArray[0] = dwCount;

	CRYPT_VERIFY_MESSAGE_PARA VerifyParams;
    VerifyParams.cbSize = sizeof (CRYPT_VERIFY_MESSAGE_PARA);
    VerifyParams.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;
    VerifyParams.hCryptProv = 0;
    VerifyParams.pfnGetSignerCertificate = NULL;
    VerifyParams.pvGetArg = NULL;


    if (CryptVerifyDetachedMessageSignature(&VerifyParams, 0, pbSignBuffer, dwSignCount,
        1, MessageArray, MessageSizeArray, &pSignerCert)) {

        statusMessage(trUtf8("Верификация проведена успешно"), true);
        exitSignMessage(false);

        displayModifiedText(pbSignBuffer, dwSignCount);

        return true;
    }
    else {

        statusMessage(trUtf8("Ошибка верификации сообщения\nCryptVerifyDetachedMessageSignature error"));
        exitSignMessage();
        return false;
    }
}

void MainWindow::displayModifiedText(BYTE *pb, DWORD cb)
{
    QString outputText(QByteArray((const char*)pb, cb).toHex());
    ui->textBrowser->setText(outputText);
}

void MainWindow::on_encrypt_pushButton_clicked()
{
    encryptFile(ui->read_lineEdit->text());
}

void MainWindow::on_decrypt_pushButton_clicked()
{
    decryptFile(ui->message_lineEdit->text());
}

void MainWindow::on_sign_pushButton_clicked()
{
    signMessage();
}

void MainWindow::on_verify_pushButton_clicked()
{
    verifySignedMessage();
}

void MainWindow::on_choose_file1_pushButton_clicked()
{
    QString filename = QFileDialog::getOpenFileName(this, trUtf8("Открыть файл"), "C://", "Все файлы (*.*);;Текстовые файлы (*.txt)");
    ui->read_lineEdit->setText(filename);
}

void MainWindow::on_choose_file2_pushButton_2_clicked()
{
    QString filename = QFileDialog::getOpenFileName(this, trUtf8("Открыть файл"), "C://", "Все файлы (*.*);;Текстовые файлы (*.txt)");
    ui->write_lineEdit->setText(filename);
}

void MainWindow::on_choose_cert_pushButton_clicked()
{
    /*hCertStore = NULL;
    pSignerCert = NULL;

    if (!(hCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0,
        NULL, CERT_SYSTEM_STORE_CURRENT_USER, CERT_STORE_NAME))) {

        statusMessage("The MY store could not be opened");
    }

    if(!(pSignerCert = CryptUIDlgSelectCertificateFromStore(
      hCertStore,
      NULL,
      NULL,
      NULL,
      CRYPTUI_SELECT_LOCATION_COLUMN,
      0,
      NULL)))
    {
        qDebug() << "Select UI failed.";
    }*/
}

void MainWindow::on_message_pushButton_clicked()
{
    QString filename = QFileDialog::getOpenFileName(this, trUtf8("Открыть файл"), "C://", "Все файлы (*.*)");
    ui->message_lineEdit->setText(filename);
}

void MainWindow::on_sign_pushButton_2_clicked()
{
    QString filename = QFileDialog::getOpenFileName(this, trUtf8("Открыть файл"), "C://", "Файл с цифровой подписью (*.detsf)");
    ui->sign_lineEdit->setText(filename);
}
