package hust.ite15.scan;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import org.json.JSONObject;
import org.json.JSONArray;

/**
 * Lớp FileBehaviours để lấy thông tin về hành vi của file từ VirusTotal API
 */
public class FileBehaviours {
    private String objectId;
    private JSONObject json;
    private static final String ERR = "ERROR: ";
    private static final String X_API_KEY = "x-apikey";
    private static final String ERR_ATTR = "error";
    private static final String ERR_MESS = "message";
    private static final String GET_ATTR = "attributes";

    /**
     * Lấy thông tin về hành vi của file từ VirusTotal API
     * @param id ID của file (SHA-256, MD5, ...)
     * @param apikey API key của VirusTotal
     * @throws IOException Nếu có lỗi khi gửi request
     * @throws InterruptedException Nếu request bị gián đoạn
     */
    public void getBehaviourSummary(String id, String apikey) throws IOException, InterruptedException {
        if (id == null || id.isEmpty()) {
            throw new IllegalArgumentException("File ID is required");
        }

        this.objectId = id;

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create("https://www.virustotal.com/api/v3/files/" + id + "/behaviour_summary"))
                .header("accept", "application/json")
                .header(X_API_KEY, apikey)
                .GET()
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        JSONObject json = new JSONObject(response.body());
        this.json = json;

        try {
            // Kiểm tra xem có lỗi không
            if (json.has(ERR_ATTR)) {
                System.out.println(ERR + json.getJSONObject(ERR_ATTR).getString(ERR_MESS) + " (" + json.getJSONObject(ERR_ATTR).getString("code") + ")");
            }
        } catch (Exception e) {
            System.out.println(ERR + e.getMessage());
        }
    }

    /**
     * In ra thông tin về hành vi của file
     */
    public void printBehaviourSummary() {
        if (json == null) {
            System.out.println("No data available for behaviour summary.");
            return;
        }

        try {
            System.out.println("\n>>> FILE BEHAVIOUR SUMMARY <<<");
            System.out.println("File ID: " + objectId);

            if (json.has("data")) {
                JSONObject data = json.getJSONObject("data");
                
                // In thông tin về các API calls được highlight
                if (data.has("calls_highlighted")) {
                    System.out.println("\nAPI Calls Highlighted:");
                    JSONArray callsHighlighted = data.getJSONArray("calls_highlighted");
                    for (int i = 0; i < callsHighlighted.length(); i++) {
                        System.out.println("- " + callsHighlighted.getString(i));
                    }
                }
                
                // In thông tin về các file được mở
                if (data.has("files_opened")) {
                    System.out.println("\nFiles Opened:");
                    JSONArray filesOpened = data.getJSONArray("files_opened");
                    for (int i = 0; i < filesOpened.length(); i++) {
                        System.out.println("- " + filesOpened.getString(i));
                    }
                }
                
                // In thông tin về các module được load
                if (data.has("modules_loaded")) {
                    System.out.println("\nModules Loaded:");
                    JSONArray modulesLoaded = data.getJSONArray("modules_loaded");
                    for (int i = 0; i < modulesLoaded.length(); i++) {
                        System.out.println("- " + modulesLoaded.getString(i));
                    }
                }
                
                // In thông tin về các mutex được tạo
                if (data.has("mutexes_created")) {
                    System.out.println("\nMutexes Created:");
                    JSONArray mutexesCreated = data.getJSONArray("mutexes_created");
                    for (int i = 0; i < mutexesCreated.length(); i++) {
                        System.out.println("- " + mutexesCreated.getString(i));
                    }
                }
                
                // In thông tin về các mutex được mở
                if (data.has("mutexes_opened")) {
                    System.out.println("\nMutexes Opened:");
                    JSONArray mutexesOpened = data.getJSONArray("mutexes_opened");
                    for (int i = 0; i < mutexesOpened.length(); i++) {
                        System.out.println("- " + mutexesOpened.getString(i));
                    }
                }
                
                // In thông tin về các process bị kết thúc
                if (data.has("processes_terminated")) {
                    System.out.println("\nProcesses Terminated:");
                    JSONArray processesTerminated = data.getJSONArray("processes_terminated");
                    for (int i = 0; i < processesTerminated.length(); i++) {
                        System.out.println("- " + processesTerminated.getString(i));
                    }
                }
                
                // In thông tin về cây process
                if (data.has("processes_tree")) {
                    System.out.println("\nProcesses Tree:");
                    JSONArray processesTree = data.getJSONArray("processes_tree");
                    for (int i = 0; i < processesTree.length(); i++) {
                        JSONObject process = processesTree.getJSONObject(i);
                        System.out.println("- " + process.getString("name") + " (PID: " + process.getString("process_id") + ")");
                    }
                }
                
                // In thông tin về các registry key được mở
                if (data.has("registry_keys_opened")) {
                    System.out.println("\nRegistry Keys Opened:");
                    JSONArray registryKeysOpened = data.getJSONArray("registry_keys_opened");
                    for (int i = 0; i < registryKeysOpened.length(); i++) {
                        System.out.println("- " + registryKeysOpened.getString(i));
                    }
                }
                
                // In thông tin về các tag
                if (data.has("tags")) {
                    System.out.println("\nTags:");
                    JSONArray tags = data.getJSONArray("tags");
                    for (int i = 0; i < tags.length(); i++) {
                        System.out.println("- " + tags.getString(i));
                    }
                }
                
                // In thông tin về các text được highlight
                if (data.has("text_highlighted")) {
                    System.out.println("\nText Highlighted:");
                    JSONArray textHighlighted = data.getJSONArray("text_highlighted");
                    for (int i = 0; i < textHighlighted.length(); i++) {
                        System.out.println("- " + textHighlighted.getString(i));
                    }
                }
            } else {
                System.out.println("No behaviour data available for this file.");
            }
        } catch (Exception e) {
            System.out.println("Error printing behaviour summary: " + e.getMessage());
            // In ra toàn bộ JSON để debug
            System.out.println("JSON Response: " + json.toString(2));
        }
    }

    /**
     * Lấy ID của file
     * @return ID của file
     */
    public String getObjectId() {
        return objectId;
    }

    /**
     * Thiết lập ID cho file
     * @param objectId ID của file
     */
    public void setObjectId(String objectId) {
        this.objectId = objectId;
    }

    /**
     * Lấy dữ liệu JSON từ API
     * @return Dữ liệu JSON
     */
    public JSONObject getJson() {
        return json;
    }
} 