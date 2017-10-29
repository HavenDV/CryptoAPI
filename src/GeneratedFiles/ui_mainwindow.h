/********************************************************************************
** Form generated from reading UI file 'mainwindow.ui'
**
** Created by: Qt User Interface Compiler version 5.9.2
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_MAINWINDOW_H
#define UI_MAINWINDOW_H

#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QButtonGroup>
#include <QtWidgets/QFrame>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QLineEdit>
#include <QtWidgets/QMainWindow>
#include <QtWidgets/QMenuBar>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QStatusBar>
#include <QtWidgets/QTextBrowser>
#include <QtWidgets/QToolBar>
#include <QtWidgets/QWidget>

QT_BEGIN_NAMESPACE

class Ui_MainWindow
{
public:
    QWidget *centralWidget;
    QLineEdit *read_lineEdit;
    QLineEdit *write_lineEdit;
    QLabel *read_label;
    QLabel *write_label;
    QLineEdit *password_lineEdit;
    QLabel *password_label;
    QFrame *line;
    QFrame *line_2;
    QLabel *enc_dec_label;
    QPushButton *encrypt_pushButton;
    QPushButton *decrypt_pushButton;
    QLabel *status_label;
    QLabel *sign_ver_label;
    QPushButton *sign_pushButton;
    QPushButton *verify_pushButton;
    QTextBrowser *textBrowser;
    QPushButton *choose_file1_pushButton;
    QPushButton *choose_file2_pushButton_2;
    QLabel *choose_cert_label;
    QPushButton *choose_cert_pushButton;
    QLineEdit *choose_cert_lineEdit;
    QLabel *message_label;
    QLineEdit *message_lineEdit;
    QPushButton *message_pushButton;
    QLabel *sign_label;
    QPushButton *sign_pushButton_2;
    QLineEdit *sign_lineEdit;
    QLabel *display_label;
    QMenuBar *menuBar;
    QToolBar *mainToolBar;
    QStatusBar *statusBar;

    void setupUi(QMainWindow *MainWindow)
    {
        if (MainWindow->objectName().isEmpty())
            MainWindow->setObjectName(QStringLiteral("MainWindow"));
        MainWindow->resize(600, 562);
        centralWidget = new QWidget(MainWindow);
        centralWidget->setObjectName(QStringLiteral("centralWidget"));
        read_lineEdit = new QLineEdit(centralWidget);
        read_lineEdit->setObjectName(QStringLiteral("read_lineEdit"));
        read_lineEdit->setGeometry(QRect(40, 80, 191, 20));
        write_lineEdit = new QLineEdit(centralWidget);
        write_lineEdit->setObjectName(QStringLiteral("write_lineEdit"));
        write_lineEdit->setGeometry(QRect(330, 80, 191, 20));
        read_label = new QLabel(centralWidget);
        read_label->setObjectName(QStringLiteral("read_label"));
        read_label->setGeometry(QRect(40, 50, 191, 16));
        write_label = new QLabel(centralWidget);
        write_label->setObjectName(QStringLiteral("write_label"));
        write_label->setGeometry(QRect(330, 50, 191, 16));
        password_lineEdit = new QLineEdit(centralWidget);
        password_lineEdit->setObjectName(QStringLiteral("password_lineEdit"));
        password_lineEdit->setGeometry(QRect(40, 150, 221, 20));
        password_label = new QLabel(centralWidget);
        password_label->setObjectName(QStringLiteral("password_label"));
        password_label->setGeometry(QRect(40, 120, 221, 16));
        line = new QFrame(centralWidget);
        line->setObjectName(QStringLiteral("line"));
        line->setGeometry(QRect(10, 180, 581, 16));
        line->setFrameShape(QFrame::HLine);
        line->setFrameShadow(QFrame::Sunken);
        line_2 = new QFrame(centralWidget);
        line_2->setObjectName(QStringLiteral("line_2"));
        line_2->setGeometry(QRect(10, 200, 581, 16));
        line_2->setFrameShape(QFrame::HLine);
        line_2->setFrameShadow(QFrame::Sunken);
        enc_dec_label = new QLabel(centralWidget);
        enc_dec_label->setObjectName(QStringLiteral("enc_dec_label"));
        enc_dec_label->setGeometry(QRect(10, 10, 261, 16));
        encrypt_pushButton = new QPushButton(centralWidget);
        encrypt_pushButton->setObjectName(QStringLiteral("encrypt_pushButton"));
        encrypt_pushButton->setGeometry(QRect(330, 150, 101, 23));
        decrypt_pushButton = new QPushButton(centralWidget);
        decrypt_pushButton->setObjectName(QStringLiteral("decrypt_pushButton"));
        decrypt_pushButton->setGeometry(QRect(450, 150, 101, 23));
        status_label = new QLabel(centralWidget);
        status_label->setObjectName(QStringLiteral("status_label"));
        status_label->setGeometry(QRect(20, 190, 561, 16));
        sign_ver_label = new QLabel(centralWidget);
        sign_ver_label->setObjectName(QStringLiteral("sign_ver_label"));
        sign_ver_label->setGeometry(QRect(10, 220, 311, 16));
        sign_pushButton = new QPushButton(centralWidget);
        sign_pushButton->setObjectName(QStringLiteral("sign_pushButton"));
        sign_pushButton->setGeometry(QRect(330, 470, 101, 23));
        verify_pushButton = new QPushButton(centralWidget);
        verify_pushButton->setObjectName(QStringLiteral("verify_pushButton"));
        verify_pushButton->setGeometry(QRect(450, 470, 101, 23));
        textBrowser = new QTextBrowser(centralWidget);
        textBrowser->setObjectName(QStringLiteral("textBrowser"));
        textBrowser->setGeometry(QRect(300, 290, 271, 161));
        choose_file1_pushButton = new QPushButton(centralWidget);
        choose_file1_pushButton->setObjectName(QStringLiteral("choose_file1_pushButton"));
        choose_file1_pushButton->setGeometry(QRect(240, 80, 31, 21));
        choose_file2_pushButton_2 = new QPushButton(centralWidget);
        choose_file2_pushButton_2->setObjectName(QStringLiteral("choose_file2_pushButton_2"));
        choose_file2_pushButton_2->setGeometry(QRect(530, 80, 31, 21));
        choose_cert_label = new QLabel(centralWidget);
        choose_cert_label->setObjectName(QStringLiteral("choose_cert_label"));
        choose_cert_label->setGeometry(QRect(40, 260, 191, 16));
        choose_cert_pushButton = new QPushButton(centralWidget);
        choose_cert_pushButton->setObjectName(QStringLiteral("choose_cert_pushButton"));
        choose_cert_pushButton->setGeometry(QRect(240, 290, 31, 21));
        choose_cert_lineEdit = new QLineEdit(centralWidget);
        choose_cert_lineEdit->setObjectName(QStringLiteral("choose_cert_lineEdit"));
        choose_cert_lineEdit->setGeometry(QRect(40, 290, 191, 21));
        message_label = new QLabel(centralWidget);
        message_label->setObjectName(QStringLiteral("message_label"));
        message_label->setGeometry(QRect(40, 330, 251, 16));
        message_lineEdit = new QLineEdit(centralWidget);
        message_lineEdit->setObjectName(QStringLiteral("message_lineEdit"));
        message_lineEdit->setGeometry(QRect(40, 360, 191, 21));
        message_pushButton = new QPushButton(centralWidget);
        message_pushButton->setObjectName(QStringLiteral("message_pushButton"));
        message_pushButton->setGeometry(QRect(240, 360, 31, 21));
        sign_label = new QLabel(centralWidget);
        sign_label->setObjectName(QStringLiteral("sign_label"));
        sign_label->setGeometry(QRect(40, 400, 191, 16));
        sign_pushButton_2 = new QPushButton(centralWidget);
        sign_pushButton_2->setObjectName(QStringLiteral("sign_pushButton_2"));
        sign_pushButton_2->setGeometry(QRect(240, 430, 31, 21));
        sign_lineEdit = new QLineEdit(centralWidget);
        sign_lineEdit->setObjectName(QStringLiteral("sign_lineEdit"));
        sign_lineEdit->setGeometry(QRect(42, 430, 191, 21));
        display_label = new QLabel(centralWidget);
        display_label->setObjectName(QStringLiteral("display_label"));
        display_label->setGeometry(QRect(300, 260, 271, 16));
        MainWindow->setCentralWidget(centralWidget);
        menuBar = new QMenuBar(MainWindow);
        menuBar->setObjectName(QStringLiteral("menuBar"));
        menuBar->setGeometry(QRect(0, 0, 600, 20));
        MainWindow->setMenuBar(menuBar);
        mainToolBar = new QToolBar(MainWindow);
        mainToolBar->setObjectName(QStringLiteral("mainToolBar"));
        MainWindow->addToolBar(Qt::TopToolBarArea, mainToolBar);
        statusBar = new QStatusBar(MainWindow);
        statusBar->setObjectName(QStringLiteral("statusBar"));
        MainWindow->setStatusBar(statusBar);

        retranslateUi(MainWindow);

        QMetaObject::connectSlotsByName(MainWindow);
    } // setupUi

    void retranslateUi(QMainWindow *MainWindow)
    {
        MainWindow->setWindowTitle(QApplication::translate("MainWindow", "CryptoAPI Application", Q_NULLPTR));
        read_label->setText(QApplication::translate("MainWindow", "\320\230\321\201\321\205\320\276\320\264\320\275\321\213\320\271 \321\204\320\260\320\271\320\273:", Q_NULLPTR));
        write_label->setText(QApplication::translate("MainWindow", "\320\232\320\276\320\275\320\265\321\207\320\275\321\213\320\271 \321\204\320\260\320\271\320\273:", Q_NULLPTR));
        password_label->setText(QApplication::translate("MainWindow", "\320\237\320\260\321\200\320\276\320\273\321\214 (\320\276\320\277\321\206\320\270\320\276\320\275\320\260\320\273\321\214\320\275\320\276):", Q_NULLPTR));
        enc_dec_label->setText(QApplication::translate("MainWindow", "\320\250\320\270\321\204\321\200\320\276\320\262\320\260\320\275\320\270\320\265 / \320\224\320\265\321\210\320\270\321\204\321\200\320\276\320\262\320\260\320\275\320\270\320\265", Q_NULLPTR));
        encrypt_pushButton->setText(QApplication::translate("MainWindow", "\320\250\320\270\321\204\321\200\320\276\320\262\320\260\321\202\321\214", Q_NULLPTR));
        decrypt_pushButton->setText(QApplication::translate("MainWindow", "\320\224\320\265\321\210\320\270\321\204\321\200\320\276\320\262\320\260\321\202\321\214", Q_NULLPTR));
        status_label->setText(QString());
        sign_ver_label->setText(QApplication::translate("MainWindow", "\320\237\320\276\320\264\320\277\320\270\321\201\321\213\320\262\320\260\320\275\320\270\320\265 \321\201\320\276\320\276\320\261\321\211\320\265\320\275\320\270\321\217 / \320\222\320\265\321\200\320\270\321\204\320\270\320\272\320\260\321\206\320\270\321\217 \321\201\320\276\320\276\320\261\321\211\320\265\320\275\320\270\321\217", Q_NULLPTR));
        sign_pushButton->setText(QApplication::translate("MainWindow", "\320\237\320\276\320\264\320\277\320\270\321\201\320\260\321\202\321\214", Q_NULLPTR));
        verify_pushButton->setText(QApplication::translate("MainWindow", "\320\222\320\265\321\200\320\270\321\204\320\270\321\206\320\270\321\200\320\276\320\262\320\260\321\202\321\214", Q_NULLPTR));
        choose_file1_pushButton->setText(QApplication::translate("MainWindow", "*", Q_NULLPTR));
        choose_file2_pushButton_2->setText(QApplication::translate("MainWindow", "*", Q_NULLPTR));
        choose_cert_label->setText(QApplication::translate("MainWindow", "\320\241\320\265\321\200\321\202\320\270\321\204\320\270\320\272\320\260\321\202:", Q_NULLPTR));
        choose_cert_pushButton->setText(QApplication::translate("MainWindow", "*", Q_NULLPTR));
        message_label->setText(QApplication::translate("MainWindow", "\320\237\320\276\320\264\320\277\320\270\321\201\321\213\320\262\320\260\320\265\320\274\320\276\320\265 / \320\262\320\265\321\200\320\270\321\204\320\270\321\206\320\270\321\200\321\203\320\265\320\274\320\276\320\265 \321\201\320\276\320\276\320\261\321\211\320\265\320\275\320\270\320\265:", Q_NULLPTR));
        message_pushButton->setText(QApplication::translate("MainWindow", "*", Q_NULLPTR));
        sign_label->setText(QApplication::translate("MainWindow", "\320\244\320\260\320\271\320\273 \321\201 \320\277\320\276\320\264\320\277\320\270\321\201\321\214\321\216:", Q_NULLPTR));
        sign_pushButton_2->setText(QApplication::translate("MainWindow", "*", Q_NULLPTR));
        display_label->setText(QApplication::translate("MainWindow", "\320\237\320\276\320\264\320\277\320\270\321\201\321\214:", Q_NULLPTR));
    } // retranslateUi

};

namespace Ui {
    class MainWindow: public Ui_MainWindow {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_MAINWINDOW_H
