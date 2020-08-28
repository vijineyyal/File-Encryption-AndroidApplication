package se.joscarsson.privify.encryption;

import android.app.ActionBar;
import android.content.Context;
import android.content.Intent;
import android.graphics.drawable.ColorDrawable;
import android.util.Pair;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageButton;
import android.widget.LinearLayout;
import android.widget.PopupWindow;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;

import se.joscarsson.privify.R;
import se.joscarsson.privify.models.ConcretePrivifyFile;
import se.joscarsson.privify.models.PrivifyFile;
import se.joscarsson.privify.ui.MainActivity;
import se.joscarsson.privify.ui.UserInterfaceHandler;

import static android.content.Context.LAYOUT_INFLATER_SERVICE;

public class EncryptionEngine {
    private Executor executor = Executors.newSingleThreadExecutor();
    private UserInterfaceHandler uiHandler;
    Context mContext;
    View view;

    Button showPopupBtn, closePopupBtn;
    PopupWindow popupWindow;
    LinearLayout linearLayout1;

    public EncryptionEngine(UserInterfaceHandler uiHandler) {
        this.uiHandler = uiHandler;
    }

    public void popupEngine(final List<PrivifyFile> files,Context mContext,View view)
    {
        this.mContext=mContext;
        this.view=view;


        List<PrivifyFile> expandedFiles = ConcretePrivifyFile.expandDirectories(files);

        for (PrivifyFile file : expandedFiles) {
           // this.totalBytes += file.getSize();
            if (!file.isEncrypted()) {
                Toast.makeText(mContext, "Encrypted...", Toast.LENGTH_SHORT).show();
                showPopup(view);
            }
        }
    }

    public void work(final List<PrivifyFile> files, final String passphrase, final boolean deletePlainFile, final PrivifyFile targetEncryptDirectory) {
        this.uiHandler.sendWorkBegun();


        this.executor.execute(new Runnable() {
            private byte[] buffer = new byte[1024 * 1024];
            private long processedBytes = 0;
            private long totalBytes = 0;
            private boolean decrypting = true;
            private String currentName;

            @Override
            public void run() {
                try {
                    List<PrivifyFile> expandedFiles = ConcretePrivifyFile.expandDirectories(files);

                    for (PrivifyFile file : expandedFiles) {
                        this.totalBytes += file.getSize();
                        if (!file.isEncrypted()) this.decrypting = false;
                    }

                    for (PrivifyFile file : expandedFiles) {
                        this.currentName = file.getName();

                        if (this.decrypting && file.isEncrypted()) {
                            decryptFile(file);
                        } else if (!this.decrypting && !file.isEncrypted()) {
                            encryptFile(file);

                        }
                    }

                    EncryptionEngine.this.uiHandler.sendWorkDone();
                } catch (Exception e) {
                    EncryptionEngine.this.uiHandler.sendWorkError();
                }
            }

            private void encryptFile(PrivifyFile plainFile) throws BadPaddingException {
                PrivifyFile encryptedFile = plainFile.asEncrypted(targetEncryptDirectory);
                //Toast.makeText(context, "Encrypting....", Toast.LENGTH_LONG).show();
                try {
                    InputStream inputStream = null;
                    OutputStream outputStream = null;

                    Pair<Cipher, byte[]> cipherPair = Cryptography.newCipher(passphrase);
                    Cipher cipher = cipherPair.first;
                    byte[] header = cipherPair.second;

                    try {
                        inputStream = plainFile.getInputStream();
                        outputStream = encryptedFile.getOutputStream();

                        outputStream.write(header);
                        outputStream = new CipherOutputStream(outputStream, cipher);

                        int bytesRead = inputStream.read(buffer);
                        while (bytesRead != -1) {
                            outputStream.write(buffer, 0, bytesRead);
                            updateProgress(bytesRead);
                            bytesRead = inputStream.read(buffer);
                        }
                    } finally {
                        if (inputStream != null) inputStream.close();
                        if (outputStream != null) outputStream.close();
                    }

                    if (deletePlainFile) {
                        garbleFile(plainFile);
                        plainFile.delete();
                    }
                } catch (Exception e) {
                    encryptedFile.delete(true);
                    throw new RuntimeException(e);
                }
            }

            private void decryptFile(PrivifyFile encryptedFile) throws BadPaddingException {
                PrivifyFile plainFile = encryptedFile.asPlain();

                try {
                    InputStream inputStream = null;
                    OutputStream outputStream = null;

                    try {
                        inputStream = encryptedFile.getInputStream();
                        Cipher cipher = Cryptography.getCipher(passphrase, inputStream);
                        outputStream = new CipherOutputStream(plainFile.getOutputStream(), cipher);

                        int bytesRead = inputStream.read(buffer);
                        while (bytesRead != -1) {
                            outputStream.write(buffer, 0, bytesRead);
                            updateProgress(bytesRead);
                            bytesRead = inputStream.read(buffer);
                        }
                    } finally {
                        if (inputStream != null) inputStream.close();
                        if (outputStream != null) outputStream.close();
                    }

                    encryptedFile.delete();
                } catch (Exception e) {
                    plainFile.delete(true);
                    throw new RuntimeException(e);
                }
            }

            /**
             * Garbles the file by writing zeros to it. As the memory is of type Flash this does
             * not guarantee that data gets fully overwritten (the driver might very well choose
             * to write the garble data to other memory cells), but this at least makes recovery
             * harder.
             */
            private void garbleFile(PrivifyFile file) throws IOException {
                OutputStream outputStream = null;
                long bytesToWrite = file.getSize();
                long bytesWritten = 0;

                if (bytesToWrite > 5 * 1024 * 1024) {
                    bytesToWrite = (long) (bytesToWrite * 0.1);
                }

                Arrays.fill(buffer, (byte) 0);

                try {
                    outputStream = file.getOutputStream();

                    while (bytesWritten < bytesToWrite) {
                        int len = bytesToWrite > buffer.length ? buffer.length : (int) bytesToWrite;
                        outputStream.write(buffer, 0, len);
                        bytesWritten += len;
                    }
                } finally {
                    if (outputStream != null) outputStream.close();
                }
            }

            private void updateProgress(int bytesRead) {
                processedBytes += bytesRead;
                int progress = (int) (processedBytes * 100 / totalBytes);
                EncryptionEngine.this.uiHandler.sendProgressUpdate(this.decrypting, this.currentName, progress);
            }
        });






    }
    public void showPopup(View view) {

        // inflate the layout of the popup window
        LayoutInflater inflater = (LayoutInflater)mContext.
                getSystemService(LAYOUT_INFLATER_SERVICE);
        View popupView = inflater.inflate(R.layout.popup, null);

        // create the popup window
        int width = LinearLayout.LayoutParams.WRAP_CONTENT;
        int height = LinearLayout.LayoutParams.WRAP_CONTENT;
        boolean focusable = true; // lets taps outside the popup also dismiss it
        final PopupWindow popupWindow = new PopupWindow(popupView, width, height, focusable);

        // show the popup window
        // which view you pass in doesn't matter, it is only used for the window tolken
        popupWindow.showAtLocation(view, Gravity.CENTER, 0, 0);

        // dismiss the popup window when touched
        popupView.setOnTouchListener(new View.OnTouchListener() {
            @Override
            public boolean onTouch(View v, MotionEvent event) {
                //popupWindow.dismiss();
                return true;
            }
        });


        //if onclick written here, it gives null pointer exception.
        Button yesbtn=(Button)popupView.findViewById(R.id.yesbtn);
        Button nobtn=(Button)popupView.findViewById(R.id.nobtn);
        yesbtn.setOnClickListener(new View.OnClickListener()
        {
            public void onClick(View v)
            {
                Toast.makeText(mContext, "Your data will be saved in Google Drive", Toast.LENGTH_LONG).show();
                popupWindow.dismiss();
            }
        });
        nobtn.setOnClickListener(new View.OnClickListener()
        {
            public void onClick(View v)
            {

                popupWindow.dismiss();
            }
        });
    }

}
