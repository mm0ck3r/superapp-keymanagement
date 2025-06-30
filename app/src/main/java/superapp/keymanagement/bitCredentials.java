package main.java.superapp.keymanagement;

public class bitCredentials {
    private final String address;
    private final String privateKey;

    bitCredentials(String address, String privateKey){
        this.address = address;
        this.privateKey = privateKey;
    }
    // TODO public String getPrivateKey -> ?
    public String getAddress(){ return address; }
    public String getPrivatekey(){ return privateKey; }

}