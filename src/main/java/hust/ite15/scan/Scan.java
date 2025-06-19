package hust.ite15.scan;

import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

import org.apache.poi.xssf.usermodel.XSSFFormulaEvaluator;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.apache.poi.xssf.usermodel.XSSFCellStyle;
import org.apache.poi.xssf.usermodel.XSSFFont;
import org.json.JSONObject;
import org.knowm.xchart.*;
import org.knowm.xchart.style.Styler.*;
import org.apache.poi.ss.util.CellUtil;
import org.apache.poi.ss.usermodel.Row;

public abstract class Scan {

    private static final String ROOT_PATH = new File(System.getProperty("user.dir")).getParent() + "/Project_1";
    private static final String X_API_KEY = "YOUR_API_KEY";
    private String name = null;
    private String objectId = null;
    private String analysisId = null;
    private int harmless =0;
    private int suspicious =0;
    private int timeout =0;
    private int malicious =0;
    private int undetected =0;
    private long time = 0;
    private JSONObject json = null;



    public void post(String apikey) throws IOException, InterruptedException {
        //POST info and save report IDs
        objectId = null;
        analysisId = null;
    }

    public void getReport(String apikey) throws IOException, InterruptedException {
        // Giả lập response từ API (bạn thay bằng response thực tế nếu có)
        String response = "{ \"data\": { \"attributes\": { \"stats\": { \"harmless\": 0, \"undetected\": 60, \"suspicious\": 0, \"malicious\": 0, \"timeout\": 2 }}}}";
        this.json = new JSONObject(response);

        if (json != null && json.has("data") && json.getJSONObject("data").has("attributes")) {
            JSONObject stats = json.getJSONObject("data").getJSONObject("attributes").getJSONObject("stats");
            this.harmless = stats.optInt("harmless", 0);
            this.undetected = stats.optInt("undetected", 0);
            this.suspicious = stats.optInt("suspicious", 0);
            this.malicious = stats.optInt("malicious", 0);
            this.timeout = stats.optInt("timeout", 0);
        }
    }

    public void printSummary() {
        System.out.println("\n>>> ANALYSIS SUMMARY <<<");
        System.out.println("> Info");
        System.out.println("Name: " + name);
        if (objectId != null && !objectId.equals(name))
            System.out.println("ID: " + objectId);
        if (getTime() == 0) {
            System.out.println("> WARNING: No finished analysis found!\n(Please wait a few seconds and update)");
            return;
        }
        System.out.println("> Analysis Stats");
        DateTimeFormatter dateformat = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());
        System.out.println("Time: " + dateformat.format(Instant.ofEpochSecond(time)));
        System.out.println("Harmless:\t" + harmless);
        System.out.println("Undetected:\t" + undetected);
        System.out.println("Suspicious:\t" + suspicious);
        System.out.println("Malicious:\t" + malicious);
        System.out.println("Timeout:\t" + timeout);
    }

    public boolean toJsonReport() {
        json = getJson();
        if (json == null) {
            System.out.println("ERROR: No report found.");
            return false;
        }
        try (FileWriter writer = new FileWriter(ROOT_PATH + "/data/JSON/" + genSaveName("report", ".json"))) {
            writer.write(getJson().toString(4));
            return true;
        } catch (Exception e) {
            try {
                System.out.println("ERROR: " + json.getJSONObject("error").getString("message") + " (" + json.getJSONObject("error").getString("code") + ")");
            } catch (Exception ee) {
                System.out.println("ERROR: " + e.getMessage());
            }
        }
        return false;
    }

    public boolean toExcelReport() {
        if (getObjectId() == null || getJson() == null) {
            System.out.println("ERROR: No report found.");
            return false;
        }
        if (getTime() == 0) {
            System.out.println("WARNING: No finished analysis found!\n(Please wait a few seconds and update)");
            return false;
        }

        try {
            // Create a new workbook
            XSSFWorkbook workbook = new XSSFWorkbook();
            XSSFSheet worksheet = workbook.createSheet("Scan Report");

            // Write the data
            writeExcel(worksheet);

            // Create output directory if it doesn't exist
            String outputDir = ROOT_PATH + "/data/CSV";
            File dir = new File(outputDir);
            if (!dir.exists()) {
                dir.mkdirs();
            }

            // Generate output filename
            String type = this instanceof FileScan ? "FILE" :
                         this instanceof URLScan ? "URL" :
                         this instanceof DomainScan ? "DOMAIN" :
                         this instanceof IPScan ? "IP" : "UNKNOWN";
            
            String outputPath = outputDir + "/" + genSaveName(type, ".xlsx");
            
            // Write to file
            try (FileOutputStream out = new FileOutputStream(outputPath)) {
                workbook.write(out);
                System.out.println("Excel report has been generated successfully at: " + outputPath);
                return true;
            } finally {
                workbook.close();
            }
        } catch (Exception e) {
            System.out.println("ERROR: Failed to write Excel report: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    public void writeExcel(XSSFSheet sheet) {
        if (sheet == null) {
            System.out.println("ERROR: Can't write anything.");
            return;
        }

        // Write basic information
        Row headerRow = sheet.getRow(0);
        if (headerRow == null) {
            headerRow = sheet.createRow(0);
        }
        headerRow.createCell(0).setCellValue("VIRUSTOTAL SCAN REPORT");
        headerRow.getCell(0).setCellStyle(createHeaderStyle(sheet.getWorkbook()));

        // Write scan type
        Row typeRow = sheet.getRow(2);
        if (typeRow == null) {
            typeRow = sheet.createRow(2);
        }
        typeRow.createCell(0).setCellValue("Scan Type:");
        typeRow.createCell(1).setCellValue(this instanceof FileScan ? "FILE" : 
                                          this instanceof URLScan ? "URL" : 
                                          this instanceof DomainScan ? "DOMAIN" : 
                                          this instanceof IPScan ? "IP" : "UNKNOWN");

        // Write name/ID
        Row nameRow = sheet.getRow(3);
        if (nameRow == null) {
            nameRow = sheet.createRow(3);
        }
        nameRow.createCell(0).setCellValue("Name/ID:");
        nameRow.createCell(1).setCellValue(name);

        // Write analysis time
        Row timeRow = sheet.getRow(4);
        if (timeRow == null) {
            timeRow = sheet.createRow(4);
        }
        timeRow.createCell(0).setCellValue("Analysis Time:");
        DateTimeFormatter dateformat = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());
        timeRow.createCell(1).setCellValue(dateformat.format(Instant.ofEpochSecond(time)));

        // Write statistics header
        Row statsHeaderRow = sheet.getRow(6);
        if (statsHeaderRow == null) {
            statsHeaderRow = sheet.createRow(6);
        }
        statsHeaderRow.createCell(0).setCellValue("SCAN STATISTICS");
        statsHeaderRow.getCell(0).setCellStyle(createHeaderStyle(sheet.getWorkbook()));

        // Write statistics
        int rowIndex = 7;
        createStatRow(sheet, rowIndex++, "Harmless", harmless);
        createStatRow(sheet, rowIndex++, "Undetected", undetected);
        createStatRow(sheet, rowIndex++, "Suspicious", suspicious);
        createStatRow(sheet, rowIndex++, "Malicious", malicious);
        createStatRow(sheet, rowIndex++, "Timeout", timeout);

        // Auto-size columns
        for (int i = 0; i < 3; i++) {
            sheet.autoSizeColumn(i);
        }
    }

    private XSSFCellStyle createHeaderStyle(XSSFWorkbook workbook) {
        XSSFCellStyle style = workbook.createCellStyle();
        XSSFFont font = workbook.createFont();
        font.setBold(true);
        font.setFontHeightInPoints((short) 14);
        style.setFont(font);
        return style;
    }

    private void createStatRow(XSSFSheet sheet, int rowIndex, String label, int value) {
        Row row = sheet.getRow(rowIndex);
        if (row == null) {
            row = sheet.createRow(rowIndex);
        }
        row.createCell(0).setCellValue(label + ":");
        row.createCell(1).setCellValue(value);
    }

    public PieChart toChart() throws IOException {
        if (getTime() == 0) {
            System.out.println("WARNING: No finished analysis found!\n(Please wait a few seconds and update)");
            return null;
        }
        // Create Chart
        DateTimeFormatter dateformat = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm").withZone(ZoneId.systemDefault());
        String shortTime = dateformat.format(Instant.ofEpochSecond(time));
        PieChart chart = new PieChartBuilder().width(800).height(600).title(this.name + " ("+shortTime+")").theme(ChartTheme.GGPlot2).build();

        // Customize Chart
        chart.getStyler().setLegendVisible(false);
        chart.getStyler().setPlotContentSize(.7);
        chart.getStyler().setStartAngleInDegrees(90);

        // Series
        chart.addSeries("harmless", this.harmless);
        chart.addSeries("undetected", this.undetected);
        chart.addSeries("suspicious", this.suspicious);
        chart.addSeries("malicious", malicious);
        chart.addSeries("timeout", this.timeout);

        return chart;
    }


    public boolean isValid() {
        return (this.name!=null);
    }

    public String genSaveName(String type) {
        DateTimeFormatter dateformat = DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm").withZone(ZoneId.systemDefault());
        String shortTime = dateformat.format(Instant.ofEpochSecond(time));
        if (time == 0)
            shortTime = "no-analysis";
        return type.toUpperCase() + "_" + name.replace("://", "-").replace(".", "-").replaceAll("[^\\dA-Za-z -]", "").replaceAll("\\s+", "-") + "_" + shortTime;
    }

    public String genSaveName(String type, String extension) {
        DateTimeFormatter dateformat = DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm").withZone(ZoneId.systemDefault());
        String shortTime = dateformat.format(Instant.ofEpochSecond(time));
        if (!extension.contains("."))
            extension = "." + extension;
        if (time == 0)
            shortTime = "no-analysis";
        return type.toUpperCase() + "_" + name.replace("://", "-").replace(".", "-").replaceAll("[^\\dA-Za-z -]", "").replaceAll("\\s+", "-") + "_" + shortTime + extension;
    }

    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }
    public String getObjectId() {
        return objectId;
    }
    public void setObjectId(String id) {
        this.objectId = id;
    }
    public int getHarmless() {
        return harmless;
    }
    public void setHarmless(int harmless) {
        this.harmless = harmless;
    }
    public int getSuspicious() {
        return suspicious;
    }
    public void setSuspicious(int suspicious) {
        this.suspicious = suspicious;
    }
    public int getTimeout() {
        return timeout;
    }
    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }
    public int getMalicious() {
        return malicious;
    }
    public void setMalicious(int malicious) {
        this.malicious = malicious;
    }
    public int getUndetected() {
        return undetected;
    }
    public void setUndetected(int undetected) {
        this.undetected = undetected;
    }
    public JSONObject getJson() {
        return json;
    }
    public void setJson(JSONObject json) {
        this.json = json;
    }
    public long getTime() {
        return time;
    }
    public void setTime(int time) {
        this.time = time;
    }
    public String getAnalysisId() {
        return analysisId;
    }
    public void setAnalysisId(String analysisId) {
        this.analysisId = analysisId;
    }

}
