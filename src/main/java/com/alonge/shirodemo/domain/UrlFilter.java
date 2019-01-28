package com.alonge.shirodemo.domain;

public class UrlFilter {
    private String url;
    private String filter;

    public UrlFilter() {
    }

    public UrlFilter(String url, String filter) {
        this.url = url;
        this.filter = filter;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getFilter() {
        return filter;
    }

    public void setFilter(String filter) {
        this.filter = filter;
    }
}
