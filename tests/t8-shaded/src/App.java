package shadedapp;

import com.aayushatharva.brotli4j.decoder.Decoder;

public class App {
    public static void main(String[] args) {
        // Reference keeps the dependency real, not just declared.
        System.out.println("brotli4j loaded: " + Decoder.class.getName());
    }
}
