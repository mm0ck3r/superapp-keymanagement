package main.java.superapp.keymanagement;

import android.content.Context;
import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import java.util.Scanner;

class PasswordHashData {
    @SerializedName("hash")
    String hash;

    public PasswordHashData(String hash) {
        this.hash = hash;
    }
}

public class walletUtil {
    public static String hashPassword(String _password){
        Argon2 argon2 = ARgon2Factory.create();
        return argon2.hash(3, 65536, 1, password.toCharArray());
    }

    public static void genMasterHash(String _password){
        String file_name = "password_hash.json";
        String hash = hashPassword(_password);
        PasswordHashData data = new PasswordHashData(hash);

        File file = new File(file_name);
        try (FileWriter writer = new FileWriter(file)) {
            writer.write(json);
            writer.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
        
    }
}
