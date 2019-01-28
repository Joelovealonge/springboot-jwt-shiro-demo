package com.alonge.shirodemo.dao;

import com.alonge.shirodemo.domain.UrlFilter;
import com.alonge.shirodemo.mapper.UrlFilterMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public class UrlFilterDao {
    @Autowired
    UrlFilterMapper urlFilterMapper;

    public List<UrlFilter> getUrlFilters() {
        return urlFilterMapper.getUrlFilters();
    }
}
