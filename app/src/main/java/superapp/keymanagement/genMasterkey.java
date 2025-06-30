package main.java.superapp.keymanagement;

import java.util.Scanner;
import main.java.superapp.keymanagement.walletUtil;


public class genMasterkey {
    public static void main(){
        Scanner scanner = new Scanner();
        System.out.println("월렛 초기 password를 입력하세요.");
        String password = scanner.nextLine();
        scanner.close();

        walletUtil.genMasterHash(password);
    }
}
