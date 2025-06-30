package main.java.superapp.keymanagement;

import java.util.Scanner;

public class Wallet {
    public static void main(){
        Scanner scanner = new Scanner();
        System.out.println("월렛 복호화용 password를 입력하세요.");
        String input = scanner.nextLine();
        System.out.println("입력한 PW: " + input);
        scanner.close();
    }
}
