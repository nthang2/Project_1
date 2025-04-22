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

        System.out.println("  ______      __        ______             __       __   __ ");
        System.out.println(" /_  __/___  / /_____ _/ / __ \\_________  / /____  / /__/ /_");
        System.out.println("  / / / __ \\/ __/ __ `/ / /_/ / ___/ __ \\/ __/ _ \\/ //_/ __/");
        System.out.println(" / / / /_/ / /_/ /_/ / / ____/ /  / /_/ / /_/  __/ ,< / /_  ");
        System.out.println("/_/  \\____/\\__/\\__,_/_/_/   /_/   \\____/\\__/\\___/_/|_|\\__/  ");
        System.out.println();
        System.out.println("1. Scan a file");
        System.out.println("2. Scan a domain");
        System.out.println("3. Scan an URL");
        System.out.println("4. Scan an IP address");
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
            case 1 -> Handler.fileScan(apiKey);
            case 2 -> Handler.domainScan(apiKey);
            case 3 -> Handler.urlScan(apiKey);
            case 4 -> Handler.ipScan(apiKey);
            case 5 -> running = false;
            default -> System.out.println("Invalid input!");
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