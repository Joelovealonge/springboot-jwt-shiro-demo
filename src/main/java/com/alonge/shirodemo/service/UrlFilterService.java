package com.alonge.shirodemo.service;

import com.alonge.shirodemo.dao.UrlFilterDao;
import com.alonge.shirodemo.domain.UrlFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UrlFilterService {
    @Autowired
    UrlFilterDao urlFilterDao;

    public List<UrlFilter> getListFilters() {
        return urlFilterDao.getUrlFilters();
    }
}
