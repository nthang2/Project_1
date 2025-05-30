package hust.ite15.scan;

import java.util.List;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.util.CellUtil;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.regex.*;

public class DomainScan extends Scan {
    //Domain input validation
    private static final String DOMAIN_PATTERN = "(?>[a-zA-Z0-9](?>[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)++(?>[a-zA-Z]{2,}|[a-zA-Z][a-zA-Z0-9-]*[a-zA-Z0-9])";
    private static final String GET_ATTR = "attributes";
    private static final String LAST_STATS = "last_analysis_stats";
    private static final String HARM = "harmless";
    private static final String MAL = "malicious";
    private static final String ENGINE = "engine_name";
    private static final Pattern pattern = Pattern.compile(DOMAIN_PATTERN);

    @Override
    public boolean isValid() {
        if (getName() == null) {
            System.out.println("ERROR: Domain name is null.");
            return false;
        }
        
        Matcher matcher = pattern.matcher(getName());
        if (matcher.matches()) {
            setObjectId(getName());
            System.out.println("Domain validated: " + getName());
            return true;
        }
        
        System.out.println("ERROR: Invalid domain format.");
        setName(null);
        return false;
    }

    @Override
    public void getReport(String apikey) throws IOException, InterruptedException {
        // if (getObjectId() == null){
        //     System.out.println("ERROR: Object ID is null.");
        //     return;
        // }
        //GET REPORT req
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://www.virustotal.com/api/v3/domains/" + getName()))
                .header("accept", "application/json")
                .header("x-apikey", apikey)
                .method("GET", HttpRequest.BodyPublishers.noBody())
                .build();
        HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());

        JSONObject json = new JSONObject(response.body());
        setJson(json);

        //SET ATTRIBUTES
        try {
            //GET BASIC INFO
            setName(json.getJSONObject("data").getString("id"));
            setObjectId(getName());

            //GET ANALYSIS
            setTime(json.getJSONObject("data").getJSONObject(GET_ATTR).getInt("last_analysis_date"));
            setHarmless(json.getJSONObject("data").getJSONObject(GET_ATTR).getJSONObject(LAST_STATS).getInt(HARM));
            setUndetected(json.getJSONObject("data").getJSONObject(GET_ATTR).getJSONObject(LAST_STATS).getInt("undetected"));
            setMalicious(json.getJSONObject("data").getJSONObject(GET_ATTR).getJSONObject(LAST_STATS).getInt(MAL));
            setSuspicious(json.getJSONObject("data").getJSONObject(GET_ATTR).getJSONObject(LAST_STATS).getInt("suspicious"));
            setTimeout(json.getJSONObject("data").getJSONObject(GET_ATTR).getJSONObject(LAST_STATS).getInt("timeout"));
        } catch (Exception e) {
            try {
                System.out.println("ERROR: " + json.getJSONObject("error").getString("message") + " (" + json.getJSONObject("error").getString("code") + ")");
            } catch (Exception ee) {
                //check if analysis not finished
                if (e.getMessage().equals("JSONObject[\"last_analysis_date\"] not found."))
                    System.out.println("WARNING: No finished analysis found!");
                else
                    System.out.println("ERROR: " + e.getMessage());
            }
        }
    }

    @Override
    public void writeExcel(XSSFSheet sheet) {
        if (sheet == null) {
            System.out.println("ERROR: Can't write anything.");
            return;
        }

        //WRITE BASIC INFO
        Row row = sheet.getRow(1);
        CellUtil.getCell(row, 0).setCellValue("type");
        CellUtil.getCell(row, 1).setCellValue("id");
        CellUtil.getCell(row, 2).setCellValue("name");
        CellUtil.getCell(row, 9).setCellValue("undetected");
        CellUtil.getCell(row, 10).setCellValue(HARM);
        CellUtil.getCell(row, 11).setCellValue("suspicious");
        CellUtil.getCell(row, 12).setCellValue(MAL);
        CellUtil.getCell(row, 13).setCellValue("timeout");
        CellUtil.getCell(row, 15).setCellValue("last_analysis_date");

        row = sheet.getRow(2);
        CellUtil.getCell(row, 0).setCellValue("domain");
        CellUtil.getCell(row, 1).setCellValue(getObjectId());
        CellUtil.getCell(row, 2).setCellValue(getName());
        CellUtil.getCell(row, 9).setCellValue(getUndetected());
        CellUtil.getCell(row, 10).setCellValue(getHarmless());
        CellUtil.getCell(row, 11).setCellValue(getSuspicious());
        CellUtil.getCell(row, 12).setCellValue(getMalicious());
        CellUtil.getCell(row, 13).setCellValue(getTimeout());
        CellUtil.getCell(row, 15).setCellValue(getTime());

        //WRITE ANALYSIS RESULTS
        row = sheet.getRow(1);
        CellUtil.getCell(row, 16).setCellValue(ENGINE);
        CellUtil.getCell(row, 17).setCellValue("category");
        CellUtil.getCell(row, 18).setCellValue("result");

        List<JSONObject> engines = new ArrayList<>();
        JSONObject json = getJson().getJSONObject("data").getJSONObject(GET_ATTR).getJSONObject("last_analysis_results");
        Iterator<String> keys = json.keys();
        while (keys.hasNext()) {
            JSONObject nestedJsonObject = json.getJSONObject(keys.next());
            engines.add(nestedJsonObject);
        }
        Collections.sort(engines, (j1, j2) -> {
            String name1 = (String) j1.get(ENGINE);
            String name2 = (String) j2.get(ENGINE);
            return name1.compareToIgnoreCase(name2);
        });


        int iRow = 2;
        for (JSONObject engine: engines) {
            row = sheet.getRow(iRow);
            if (row == null)
                row = sheet.createRow(iRow);
            CellUtil.getCell(row, 16).setCellValue(engine.getString(ENGINE));
            CellUtil.getCell(row, 17).setCellValue(engine.getString("category"));
            if (!engine.isNull("result")) {
                CellUtil.getCell(row, 18).setCellValue(engine.getString("result"));
            }
            iRow++;
        }
        if (iRow < 101) {
            row = sheet.getRow(101);
            CellUtil.getCell(row, 16).setBlank();
        }

        // WRITE OTHER DOMAIN INFOS
        row = sheet.getRow(1);
        CellUtil.getCell(row, 3).setCellValue("creation_date");
        CellUtil.getCell(row, 4).setCellValue("whois_date");
        CellUtil.getCell(row, 5).setCellValue("tld");
        CellUtil.getCell(row, 8).setCellValue("registrar");
        CellUtil.getCell(row, 19).setCellValue("reputation");
        CellUtil.getCell(row, 20).setCellValue(HARM);
        CellUtil.getCell(row, 21).setCellValue(MAL);

        json = getJson().getJSONObject("data").getJSONObject(GET_ATTR);
        row = sheet.getRow(2);
        CellUtil.getCell(row, 3).setCellValue(json.getLong("creation_date"));
        CellUtil.getCell(row, 4).setCellValue(json.getLong("whois_date"));
        CellUtil.getCell(row, 5).setCellValue(json.getString("tld"));
        CellUtil.getCell(row, 8).setCellValue(json.getString("registrar"));
        CellUtil.getCell(row, 19).setCellValue(json.getInt("reputation"));
        CellUtil.getCell(row, 20).setCellValue(json.getJSONObject("total_votes").getInt(HARM));
        CellUtil.getCell(row, 21).setCellValue(json.getJSONObject("total_votes").getInt(MAL));

        // WRITE CATEGORIES
        row = sheet.getRow(1);
        CellUtil.getCell(row, 6).setCellValue("categorizers");
        CellUtil.getCell(row, 7).setCellValue("categories");

        json = getJson().getJSONObject("data").getJSONObject(GET_ATTR).getJSONObject("categories");
        keys = json.keys();
        iRow = 2;
        while (keys.hasNext()) {
            String key = keys.next();
            row = sheet.getRow(iRow);
            if (row == null)
                row = sheet.createRow(iRow);
            CellUtil.getCell(row, 6).setCellValue(key);
            CellUtil.getCell(row, 7).setCellValue(json.getString(key));
            iRow++;
        }

        // WRITE WHOIS
        row = sheet.getRow(1);
        CellUtil.getCell(row, 22).setCellValue("whois");
        String whois = getJson().getJSONObject("data").getJSONObject(GET_ATTR).getString("whois");
        iRow = 2;
        for (String line : whois.split("\n")) {
            String[] info = line.split(": ");
            row = sheet.getRow(iRow);
            CellUtil.getCell(row, 22).setCellValue(info[0]);
            if (info.length >= 2) {
                CellUtil.getCell(row, 23).setCellValue(info[1]);
            }
            iRow++;
        }
    }
}
