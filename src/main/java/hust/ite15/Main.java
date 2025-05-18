package hust.ite15;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;
import java.util.Scanner;

public class Main {
    public static String apiKey = "";
    private static boolean running = true;
    public static Scanner input = new Scanner(System.in);

    private static boolean loadConfig() {
        try {
            Properties prop = new Properties();
            String configPath = System.getProperty("user.dir") + "/src/main/resources/config.properties";
            prop.load(new FileInputStream(configPath));
            apiKey = prop.getProperty("apikey");
            return true;
        } catch (IOException e) {
            return false;
        }
        
    }

    private static void mainLoop() {
        int choice = 0;

        System.out.println(" __   ___             _       _        _   ___               ");
        System.out.println(" \\ \\ / (_)_ _ _  _ __| |_ ___| |_ __ _| | / __| __ __ _ _ _  ");
        System.out.println("  \\ V /| | '_| || (_-<  _/ _ \\  _/ _` | | \\__ \\/ _/ _` | ' \\ ");
        System.out.println("   \\_/ |_|_|  \\_,_/__/\\__\\___/\\__\\__,_|_| |___/\\__\\__,_|_||_|");
        System.out.println("                                                             ");
        System.out.println("1. File");
        System.out.println("2. Domain");
        System.out.println("3. URL");
        System.out.println("4. IP address");
        System.out.println("5. Exit");

        System.out.printf("\nEnter a choice: ");

        if (input.hasNextInt()) {
            choice = input.nextInt();
            input.nextLine();
        } else {
            input.nextLine();
            System.out.println("Invalid input!");
        }

        switch (choice) {
            case 1:
                Handler.fileScan(apiKey);
                break;
            case 2:
                Handler.domainScan(apiKey);
                break;
            case 3:
                Handler.urlScan(apiKey);
                break;
            case 4:
                Handler.ipScan(apiKey);
                break;
            case 5:
                running = false;
                break;
            default:
                System.out.println("Invalid input!");
        }
    }

    public static void main(String[] args) {
        if (!loadConfig()) {
            System.out.println("Failed to load config file");
            return;
        }

        while (running) {
            mainLoop();
        }
    }
}