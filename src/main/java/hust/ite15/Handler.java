package hust.ite15;

import java.io.File;
import java.util.Scanner;

public class Handler {
    static Scanner input = new Scanner(System.in);

    public static void fileScan(String apikey) {
        int choice = 0;

        System.out.printf("\nFILE ANALYSIS\n");
        System.out.println("1. Upload a file");
        System.out.println("2. Enter file's MD5/SHA-1/SHA-256 hash");

        System.out.printf("\nEnter a choice: ");

        if (input.hasNextInt()) {
            choice = input.nextInt();
            input.nextLine();
        }
        else {
            input.nextLine();
            System.out.println("Invalid input!");
        }

        switch (choice) {
            case 1 -> {
                System.out.print("Enter ABSOLUTE file path: ");
                String path = input.nextLine().strip();

                File file = new File(path);
                if (!file.exists() || !file.isFile()) {
                    System.out.println("Invalid file path!");
                }

            }
            case 2 -> {
                System.out.print("Enter hash: ");
                String hash = input.nextLine().strip();
                if (!hash.matches("[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}")) {
                    System.out.println("Invalid hash!");
                    return;
                }

                System.out.println("Scanning file with hash: " + hash + " with apikey " + apikey);
            }
            default -> System.out.println("Invalid input!");
        }
    }

    public static void domainScan(String apikey) {
        System.out.printf("\nDOMAIN ANALYSIS\n");
        System.out.printf("\nEnter domain: ");

        String domain = input.nextLine().strip();
        System.out.println("Scanning domain: " + domain + " with apikey " + apikey);
    }

    public static void urlScan(String apikey) {
        System.out.printf("\nURL ANALYSIS\n");
        System.out.printf("\nEnter URL: ");

        String url = input.nextLine().strip();
        System.out.println("Scanning URL address: " + url);
    }

    public static void ipScan(String apikey) {
        System.out.printf("\nIP ANALYSIS\n");
        System.out.printf("\nEnter IP: ");

        String ip = input.nextLine().strip();
        System.out.println("Scanning IP address: " + ip + " with apikey " + apikey);
    }
}
