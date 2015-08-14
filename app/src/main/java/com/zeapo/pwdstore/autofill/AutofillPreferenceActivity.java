package com.zeapo.pwdstore.autofill;

import android.app.DialogFragment;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.graphics.drawable.Drawable;
import android.os.AsyncTask;
import android.os.Bundle;
import android.support.v4.app.NavUtils;
import android.support.v4.app.TaskStackBuilder;
import android.support.v4.view.MenuItemCompat;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.LinearLayoutManager;
import android.support.v7.widget.RecyclerView;
import android.support.v7.widget.SearchView;
import android.util.Pair;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;

import com.zeapo.pwdstore.R;

import java.util.HashMap;
import java.util.List;

public class AutofillPreferenceActivity extends AppCompatActivity {

    private RecyclerView recyclerView;
    AutofillRecyclerAdapter recyclerAdapter; // let fragment have access
    private RecyclerView.LayoutManager layoutManager;

    private PackageManager pm;

    private boolean recreate;

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.autofill_recycler_view);
        recyclerView = (RecyclerView) findViewById(R.id.autofill_recycler);

        layoutManager = new LinearLayoutManager(this);
        recyclerView.setLayoutManager(layoutManager);
        recyclerView.addItemDecoration(new DividerItemDecoration(this, DividerItemDecoration.VERTICAL_LIST));

        pm = getPackageManager();

        new populateTask().execute();

        setTitle("Autofill Apps");
    }

    private class populateTask extends AsyncTask<Void, Void, Void> {
        @Override
        protected void onPreExecute() {
            findViewById(R.id.progress_bar).setVisibility(View.VISIBLE);
        }

        @Override
        protected Void doInBackground(Void... params) {
            Intent intent = new Intent(Intent.ACTION_MAIN);
            intent.addCategory(Intent.CATEGORY_LAUNCHER);
            List<ResolveInfo> allApps = pm.queryIntentActivities(intent, 0);

            HashMap<String, Pair<Drawable, String>> iconMap = new HashMap<>(allApps.size());
            for (ResolveInfo app : allApps) {
                iconMap.put(app.activityInfo.packageName
                        , Pair.create(app.loadIcon(pm), app.loadLabel(pm).toString()));
            }

            recyclerAdapter = new AutofillRecyclerAdapter(allApps, iconMap, pm, AutofillPreferenceActivity.this);
            return null;
        }

        @Override
        protected void onPostExecute(Void aVoid) {
            findViewById(R.id.progress_bar).setVisibility(View.GONE);

            recyclerView.setAdapter(recyclerAdapter);

            recreate = false;
            Bundle extras = getIntent().getExtras();
            if (extras != null) {
                recreate = true;
                recyclerView.scrollToPosition(recyclerAdapter.getPosition(extras.getString("packageName")));
                showDialog(extras.getString("packageName"), extras.getString("appName"));
            }
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.autofill_preference, menu);
        MenuItem searchItem = menu.findItem(R.id.action_search);
        SearchView searchView = (SearchView) MenuItemCompat.getActionView(searchItem);

        searchView.setOnQueryTextListener(new SearchView.OnQueryTextListener() {
            @Override
            public boolean onQueryTextSubmit(String s) {
                return false;
            }

            @Override
            public boolean onQueryTextChange(String s) {
                if (recyclerAdapter != null) {
                    recyclerAdapter.filter(s);
                }
                return true;
            }
        });

        return super.onCreateOptionsMenu(menu);
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            // in service, we CLEAR_TASK. then we set the recreate flag.
            // something of a hack, but w/o CLEAR_TASK, behaviour was unpredictable
            case android.R.id.home:
                Intent upIntent = NavUtils.getParentActivityIntent(this);
                if (recreate) {
                    TaskStackBuilder.create(this)
                            .addNextIntentWithParentStack(upIntent)
                            .startActivities();
                } else {
                    NavUtils.navigateUpTo(this, upIntent);
                }
                return true;
        }
        return super.onOptionsItemSelected(item);
    }

    public void showDialog(String packageName, String appName) {
        DialogFragment df = new AutofillFragment();
        Bundle args = new Bundle();
        args.putString("packageName", packageName);
        args.putString("appName", appName);
        args.putInt("position", recyclerAdapter.getPosition(packageName));
        df.setArguments(args);
        df.show(getFragmentManager(), "autofill_dialog");
    }
}
