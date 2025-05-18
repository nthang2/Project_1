package hust.ite15;

import java.io.File;
import java.util.Scanner;
import hust.ite15.scan.*;

public class Handler {
    static Scanner input = new Scanner(System.in);

    public static void fileScan(String apikey) {
        System.out.printf("\nFILE ANALYSIS\n");
        System.out.println("1. Upload a file");
        System.out.println("2. Enter file's MD5/SHA-1/SHA-256 or ID hash");
        System.out.println("3. Get file download URL");
        System.out.println("4. Get file behaviour summary");

        System.out.printf("\nEnter a choice: ");

        int choice = 0;
        if (input.hasNextInt()) {
            choice = input.nextInt();
            input.nextLine();
        } else {
            input.nextLine();
            System.out.println("Invalid input!");
            return;
        }

        switch (choice) {
            case 1 -> {
                System.out.print("Enter ABSOLUTE file path: ");
                String path = input.nextLine().strip();

                File file = new File(path);
                if (!file.exists() || !file.isFile()) {
                    System.out.println("Invalid file path!");
                    return;
                }
                
                FileScan fileScan = new FileScan();
                fileScan.setFilepath(file);
                try {
                    fileScan.post(apikey);
                    waitForAnalysis(fileScan, apikey);
                } catch (Exception e) {
                    System.out.println("Error scanning file: " + e.getMessage());
                }
            }
            case 2 -> {
                System.out.print("Enter hash: ");
                String hash = input.nextLine().strip();
                if (!hash.matches("[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}")) {
                    System.out.println("Invalid hash!");
                    return;
                }

                FileScan fileScan = new FileScan();
                try {
                    System.out.println("Getting report for hash: " + hash);
                    fileScan.getFileReport(hash, apikey);
                    waitForAnalysis(fileScan, apikey);
                } catch (Exception e) {
                    System.out.println("Error getting file report: " + e.getMessage());
                }
            }
            case 3 -> {
                System.out.print("Enter file hash (SHA-256, MD5, ...): ");
                String hash = input.nextLine().strip();
                if (!hash.matches("[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}")) {
                    System.out.println("Invalid hash!");
                    return;
                }

                FileScan fileScan = new FileScan();
                try {
                    System.out.println("Getting download URL for hash: " + hash);
                    String downloadUrl = fileScan.getFileDownloadURL(hash, apikey);
                    System.out.println("Download URL: " + downloadUrl);
                } catch (Exception e) {
                    System.out.println("Error getting download URL: " + e.getMessage());
                }
            }
            case 4 -> {
                System.out.print("Enter file hash or ID (SHA-256, MD5, ...): ");
                String hash = input.nextLine().strip();
                if (!hash.matches("[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}")) {
                    System.out.println("Invalid hash!");
                    return;
                }

                FileBehaviours fileBehaviours = new FileBehaviours();
                try {
                    System.out.println("Getting behaviour summary for hash: " + hash);
                    fileBehaviours.getBehaviourSummary(hash, apikey);
                    fileBehaviours.printBehaviourSummary();
                } catch (Exception e) {
                    System.out.println("Error getting behaviour summary: " + e.getMessage());
                }
            }
            default -> System.out.println("Invalid input!");
        }
    }

    public static void domainScan(String apikey) {
        System.out.printf("\nDOMAIN ANALYSIS\n");
        System.out.printf("\nEnter domain: ");

        String domain = input.nextLine().strip();
        DomainScan domainScan = new DomainScan();
        domainScan.setName(domain);
        try {
            domainScan.isValid();
            domainScan.post(apikey);
            waitForAnalysis(domainScan, apikey);
        } catch (Exception e) {
            System.out.println("Error scanning domain: " + e.getMessage());
        }
    }

    public static void urlScan(String apikey) {
        System.out.printf("\nURL ANALYSIS\n");
        System.out.println("1. Rescan URL with ID");
        System.out.println("2. Scan new URL");
        System.out.printf("\nEnter a choice: ");

        int choice = 0;
        if (input.hasNextInt()) {
            choice = input.nextInt();
            input.nextLine();
        } else {
            input.nextLine();
            System.out.println("Invalid input!");
            return;
        }

        switch (choice) {
            case 1 -> urlRescan(apikey);
            case 2 -> scanNewUrl(apikey);
            default -> System.out.println("Invalid choice!");
        }
    }

    private static void scanNewUrl(String apikey) {
        System.out.printf("\nEnter URL: ");
        String url = input.nextLine().strip();
        URLScan urlScan = new URLScan();
        urlScan.setName(url);
        try {
            urlScan.post(apikey);
            waitForAnalysis(urlScan, apikey);
        } catch (Exception e) {
            System.out.println("Error scanning URL: " + e.getMessage());
        }
    }

    public static void ipScan(String apikey) {
        System.out.printf("\nIP ANALYSIS\n");
        System.out.printf("\nEnter IP: ");

        String ip = input.nextLine().strip();
        IPScan ipScan = new IPScan();
        ipScan.setName(ip);
        
        // Kiểm tra xem IP address có hợp lệ không
        if (!ipScan.isValid()) {
            System.out.println("Invalid IP address. Please try again.");
            return;
        }
        
        try {
            // ipScan.post(apikey);
            ipScan.getReport(apikey);
            waitForAnalysis(ipScan, apikey);
        } catch (Exception e) {
            System.out.println("Error scanning IP: " + e.getMessage());
        }
    }
    
    /**
     * Đợi và thử lại khi phân tích chưa hoàn thành
     * @param scan Đối tượng scan
     * @param apikey API key
     * @throws Exception Nếu có lỗi xảy ra
     */
    private static void waitForAnalysis(Scan scan, String apikey) throws Exception {
        // Thử lấy báo cáo lần đầu
        scan.getReport(apikey);
        
        // Nếu phân tích chưa hoàn thành, thử lại tối đa 5 lần
        int maxRetries = 5;
        int retryCount = 0;
        
        while (scan.getTime() == 0 && retryCount < maxRetries) {
            System.out.println("Analysis not complete yet. Waiting... (Attempt " + (retryCount + 1) + "/" + maxRetries + ")");
            
            // Đợi 5 giây
            Thread.sleep(5000);
            
            // Thử lấy báo cáo lại
            scan.getReport(apikey);
            
            // Tăng số lần thử
            retryCount++;
        }
        
        // In kết quả phân tích
        scan.printSummary();
    }

    private static void urlRescan(String apikey) {
        System.out.printf("\nEnter URL ID to rescan: ");
        String urlId = input.nextLine().strip();
        
        URLScan urlScan = new URLScan();
        urlScan.setObjectId(urlId);
        try {
            System.out.println("Sending rescan request...");
            urlScan.reAnalyze(apikey);
            
            System.out.println("Waiting for analysis to complete...");
            waitForAnalysis(urlScan, apikey);
            
            System.out.println("Rescan completed successfully!");
        } catch (Exception e) {
            System.out.println("Error during URL rescan: " + e.getMessage());
        }
    }
}
